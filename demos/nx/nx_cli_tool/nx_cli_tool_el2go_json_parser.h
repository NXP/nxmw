/*
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#include "cJSON.h"

#ifdef _WIN32
#include <direct.h>
#define MKDIR(path) _mkdir(path)
#else
#include <sys/stat.h>
#define MKDIR(path) mkdir(path, 0777)
#endif

#define FILE_CHUNK_SIZE 1023

#if defined(_MSC_VER)
#define OS_PATH_SEPARATOR "\\"
#else
#define OS_PATH_SEPARATOR "/"
#endif

#define NXCLITOOL_MAX_DIR_LENGTH 512
#define NXCLITOOL_MAX_PART1_DIR_LENGTH 50
#define NXCLITOOL_MAX_FILE_LENGTH 40
#define NXCLITOOL_MAX_EXTRA_DIR_LENGTH (NXCLITOOL_MAX_DIR_LENGTH + NXCLITOOL_MAX_PART1_DIR_LENGTH)
#define NXCLITOOL_MAX_FILE_NAME_LENGTH (NXCLITOOL_MAX_EXTRA_DIR_LENGTH + NXCLITOOL_MAX_FILE_LENGTH)
#define NXCLITOOL_MAX_OPENSSL_CMD_LENGHT 2048

int handleAppCertExtractionFromJson(const char *json_str, char *dirname);
int cjp_get_json_str(char **json_string, size_t *json_strlen, FILE *fp);
int parseJsonAndExtractAppCert(char *json_file, char *dirname);

void nxclitool_show_command_help_el2go_parser()
{
    printf("\nUSAGE: nxclitool el2go-parser [OPTIONS]\n");
    printf("OPTIONS:\n");
    printf("  -in <path>\t\t Path to input JSON file\n");
    printf("  -out <folderpath>\t\t Path to output JSON file\n");
    printf("\n");
}

int handleAppCertExtractionFromJson(const char *json_str, char *dirname)
{
    int ret = -1;
    char folderName[NXCLITOOL_MAX_EXTRA_DIR_LENGTH];
    char filePath[NXCLITOOL_MAX_FILE_NAME_LENGTH];
    char pemFilePath[NXCLITOOL_MAX_FILE_NAME_LENGTH];
    int templateId = 0;
    cJSON *root    = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != json_str);
    ENSURE_OR_GO_CLEANUP(NULL != dirname);

    if (strlen(dirname) > NXCLITOOL_MAX_DIR_LENGTH) {
        LOG_E("Please give foldername within 512bytes");
        return ret;
    }

    root = cJSON_Parse(json_str);
    if (!root) {
        LOG_E("Error parsing JSON\n");
        return ret;
    }

    // Print metadata
    cJSON *metadata = cJSON_GetObjectItem(root, "metadata");
    if (metadata) {
        LOG_I("metadata:\n");
        LOG_I("  domain: %s", cJSON_GetObjectItem(metadata, "domain")->valuestring);
        LOG_I("  jobId: %s", cJSON_GetObjectItem(metadata, "jobId")->valuestring);
        LOG_I("  jobStatus: %s\n", cJSON_GetObjectItem(metadata, "jobStatus")->valuestring);
    }
    else {
        LOG_E("Error metadata parsing JSON:\n");
        goto cleanup;
    }

    // Print content array
    cJSON *content = cJSON_GetObjectItem(root, "content");
    if (cJSON_IsArray(content)) {
        LOG_I("content:\n");
        // Get the first item to extract templateId
        cJSON *firstItem = cJSON_GetArrayItem(content, 0);
        if (firstItem) {
            templateId = cJSON_GetObjectItem(firstItem, "x509TemplateId")->valueint;
            // Convert templateId to folder name
            ret = snprintf(folderName,
                sizeof(folderName),
                "%s%sx509_job_template_id_%d_der_files",
                dirname,
                OS_PATH_SEPARATOR,
                templateId);
            ENSURE_OR_GO_CLEANUP(ret >= 0);
            MKDIR(folderName);
        }
        else {
            LOG_E("Error parsing JSON:\n");
            goto cleanup;
        }

        cJSON *item = NULL;
        cJSON_ArrayForEach(item, content)
        {
            char *deviceId = cJSON_GetObjectItem(item, "deviceId")->valuestring;
            templateId     = cJSON_GetObjectItem(item, "x509TemplateId")->valueint;
            int certId     = cJSON_GetObjectItem(item, "x509CertificateId")->valueint;
            char *cert     = cJSON_GetObjectItem(item, "x509Certificate")->valuestring;

            LOG_I("x509TemplateId: %d", templateId);
            LOG_I("x509CertificateId: %d", certId);
            LOG_I("deviceId: %s", deviceId);
            LOG_D("x509Certificate:%s\n", cert);
#if defined(SSS_HAVE_LOG_SILENT) && (SSS_HAVE_LOG_SILENT)
            (void)certId;
#endif
            // Create PEM and DER file paths
            ret = snprintf(pemFilePath, sizeof(pemFilePath), "%s%s%s.pem", folderName, OS_PATH_SEPARATOR, deviceId);
            ENSURE_OR_GO_CLEANUP(ret >= 0);
            ret = snprintf(filePath, sizeof(filePath), "%s%s%s.der", folderName, OS_PATH_SEPARATOR, deviceId);
            ENSURE_OR_GO_CLEANUP(ret >= 0);
            ret = -1;

            // Write PEM certificate to temporary file
            FILE *pem_fh = fopen(pemFilePath, "wb");
            if (!pem_fh) {
                LOG_E("Unable to open file to save PEM cert");
                goto cleanup;
            }
            if (fwrite(cert, 1, strlen(cert), pem_fh) != strlen(cert)) {
                LOG_E("Failed to write PEM cert to file");
                fclose(pem_fh);
                goto cleanup;
            }
            fclose(pem_fh);

            // Convert PEM to DER using OpenSSL CLI
            char command[NXCLITOOL_MAX_OPENSSL_CMD_LENGHT];
            ret = snprintf(
                command, sizeof(command), "openssl x509 -in \"%s\" -outform DER -out \"%s\"", pemFilePath, filePath);
            ENSURE_OR_GO_CLEANUP(ret >= 0);
            ret         = -1;
            int cmd_ret = system(command);
            if (cmd_ret != 0) {
                LOG_E("OpenSSL conversion failed for %s", deviceId);
                goto cleanup;
            }

            // Delete the temporary PEM file
            if (remove(pemFilePath) != 0) {
                LOG_E("Failed to delete temporary PEM file: %s", pemFilePath);
            }

            LOG_I("Successfully converted PEM to DER for deviceId: %s\n\n", deviceId);
        }
        ret = 0;
    }
    else {
        LOG_E("Error parsing JSON:\n");
    }

cleanup:
    if (root) {
        cJSON_Delete(root);
    }
    return ret;
}

int cjp_get_json_str(char **json_string, size_t *json_strlen, FILE *fp)
{
    int ret                   = -1;
    char *pjson_string        = NULL;
    size_t string_buff_length = 0;
    size_t bytes_read         = 0;

    LOG_D("FN: %s", __FUNCTION__);
    ENSURE_OR_GO_EXIT(fp != NULL);

    *json_strlen = 0; // Initialize to avoid tainted usage

    *json_string = malloc(FILE_CHUNK_SIZE + 1);
    ENSURE_OR_GO_EXIT(*json_string != NULL);

    string_buff_length = FILE_CHUNK_SIZE + 1;
    pjson_string       = *json_string;

    while ((bytes_read = fread(pjson_string, 1, FILE_CHUNK_SIZE, fp)) > 0) {
        // Check for overflow before addition
        if (*json_strlen > SIZE_MAX - bytes_read) {
            LOG_E("Potential overflow detected. File too large.");
            goto exit;
        }

        *json_strlen += bytes_read;

        if (*json_strlen >= string_buff_length - 1) {
            size_t new_length = string_buff_length + FILE_CHUNK_SIZE;
            if (new_length < string_buff_length) { // Overflow check
                LOG_E("Buffer size overflow detected.");
                goto exit;
            }

            char *temp_json_buffer = realloc(*json_string, new_length);
            if (temp_json_buffer == NULL) {
                LOG_E("Failed to extend json_string. JSON file too large!!");
                free(*json_string);
                *json_string = NULL;
                if (fp != NULL) {
                    if (0 != fclose(fp)) {
                        LOG_E("Failed to close the file handle!");
                        ret = -1;
                    }
                    fp = NULL;
                }
                goto exit;
            }

            *json_string       = temp_json_buffer;
            string_buff_length = new_length;
            pjson_string       = *json_string + *json_strlen;
        }
        else {
            break;
        }
    }

    // Ensure null termination safely
    if (*json_strlen < string_buff_length) {
        pjson_string               = *json_string;
        pjson_string[*json_strlen] = '\0';
        ret                        = 0;
    }
    else {
        LOG_E("Buffer overflow risk detected.");
    }

exit:

    if (ret != 0) {
        free(*json_string);
        *json_string = NULL;
        *json_strlen = 0;
    }
    return ret;
}

int parseJsonAndExtractAppCert(char *json_file, char *dirname)
{
    int ret                   = -1;
    char *json_string         = NULL;
    size_t json_string_length = 0;

    LOG_D("FN: %s", __FUNCTION__);

    ENSURE_OR_GO_CLEANUP(NULL != json_file);
    ENSURE_OR_GO_CLEANUP(NULL != dirname);

    FILE *fp = NULL;

    // Open JSON file (path input from command line argument)
    LOG_D("Opening the json input file");
    if ((fp = fopen(json_file, "rb")) == NULL) {
        LOG_E("Invalid file path provided!!");
        goto cleanup;
    }

    // Store the json file contents in a string
    ret = cjp_get_json_str(&json_string, &json_string_length, fp);
    ENSURE_OR_GO_CLEANUP(ret == 0);
    ENSURE_OR_GO_CLEANUP(json_string_length > 0);
    ret = -1;
    ret = handleAppCertExtractionFromJson(json_string, dirname);
    ENSURE_OR_GO_CLEANUP(ret == 0);

    if (fp != NULL) {
        if (0 != fclose(fp)) {
            LOG_E("Failed to close the file handle!");
            ret = -1;
        }
    }

cleanup:
    if (json_string != NULL) {
        free(json_string);
        json_string = NULL;
    }
    if (ret != 0) {
        LOG_E("Failed to parse the JSON file!!");
    }
    return ret;
}

sss_status_t nxclitool_el2go_json_parser(char *json_file, char *dirname, bool dirname_flag)
{
    sss_status_t status = kStatus_SSS_Fail;
    int ret             = -1;

    ENSURE_OR_GO_CLEANUP(NULL != json_file);
    ENSURE_OR_GO_CLEANUP(FALSE != dirname_flag);
    ENSURE_OR_GO_CLEANUP(NULL != dirname);

    ret = parseJsonAndExtractAppCert(json_file, dirname);
    ENSURE_OR_GO_CLEANUP(ret == 0);
    status = kStatus_SSS_Success;

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("El2go Parser Success !!!...");
    }
    else {
        LOG_E("El2go Parser Failed !!!...");
    }
    return status;
}