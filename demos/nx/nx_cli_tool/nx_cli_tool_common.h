/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#include <stdio.h>
#include <stdlib.h>
#include <nxEnsure.h>
#include <fsl_sss_nx_auth.h>
#include <nxLog_msg.h>
#include <string.h>
#include <fsl_sss_util_asn1_der.h>

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/base64.h"
#include "mbedtls/pem.h"
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/pem.h>
#include <openssl/x509.h>
#endif

#define MAX_HOST_NAME_LEN 20
#define MAX_PORT_NAME_LEN 50
#define MAX_CERT_BUF_LEN 1024
#define MAX_KEY_LEN 1024
#define MAX_FILE_PATH_LEN 512
#define MAX_FILE_DATA_BUF_SIZE 2048
#define MAX_PEM_MARKER_LEN 50
#define NXCLITOOL_SSS_BOOT_SSS_PCSC_READER_DEFAULT "NXP Semiconductors P71 T=0, T=1 Driver 0"
#define NXCLITOOL_SSS_BOOT_SSS_COMPORT_DEFAULT "\\\\.\\COM7"
#define NXCLITOOL_SSS_BOOT_SSS_I2C_PORT_DEFAULT "/dev/ttyACM0"
#define TEMP_FILE_NAME "nxclitool_temp"
#define CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc)          \
    if (i >= argc) {                                           \
        LOG_E("Invalid command. Please check the parameters"); \
        return 1;                                              \
    }

typedef struct
{
    sss_session_t session;
    sss_key_store_t ks;
    sss_session_t host_session;
    sss_key_store_t host_ks;
    nx_connect_ctx_t nx_open_ctx;
} nxclitool_sss_boot_ctx_t;

typedef enum
{
    NXCLITOOL_KEY_TYPE_LEAF = 0,
    NXCLITOOL_KEY_TYPE_ROOT_CA,
    NXCLITOOL_KEY_TYPE_PUBLIC,
    NXCLITOOL_KEY_TYPE_PRIVATE,
    NXCLITOOL_KEY_TYPE_PAIR,
    NXCLITOOL_KEY_TYPE_NA
} NXCLITOOL_KEY_TYPE_t;

typedef enum
{
    NXCLITOOL_OPERATION_NONE = 0,
    NXCLITOOL_OPERATION_SIGN,
    NXCLITOOL_OPERATION_ECDH
} NXCLITOOL_OPERATION_t;

void nxclitool_show_usage()
{
    printf("USAGE: nxclitool [COMMAND] [OPTIONS]\n");
    printf("\n");
    printf("  Command Line Interface for SA\n");
    printf("\n");
    printf("COMMAND:\n");
    printf("  certrepo-activate\t\tActivates a certificate repository\n");
    printf("  certrepo-create\t\tCreates certificate repository\n");
    printf("  certrepo-load-cert\t\tLoads certificates in repository\n");
    printf("  certrepo-load-key\t\tLoads keys in repository\n");
    printf("  certrepo-load-mapping\t\tLoads mapping in repository\n");
    printf("  certrepo-read-cert\t\tReads certificates from repository and store in a file\n");
    printf("  certrepo-read-metadata\tReads metadata from repository\n");
    printf("  certrepo-reset\t\tResets certificate repository\n");
    printf("  connect\t\t\tStores connection properties for SA\n");
    printf("  create-bin\t\t\tCreates a standard data file inside SA\n");
    printf("  disconnect\t\t\tDeletes connection properties. Does not require additional options\n");
    printf("  getbin\t\t\tGet data from standard data file in SA\n");
    printf("  genkey\t\t\tGenerates ECC Key and stores the public key to a file\n");
    printf("  get-ref-key\t\t\tGenerates reference key from a public key and key ID\n");
    printf("  list-eckey\t\t\tFetches the list and properties of EC keys inside SA\n");
    printf("  list-fileid\t\t\tFetches the list of file IDs inside SA\n");
    printf("  get-uid\t\t\tGet UID from SA. No additional options required\n");
    printf("  rand\t\t\t\tGenerate specified number of random bytes\n");
    printf("  setbin\t\t\tSets data to a standard data file inside SA\n");
    printf("  setkey\t\t\tSet a private key inside SA\n");
    printf("  i2c_mgnt\t\t\tSet config i2c management SA\n");
    printf("\n");
    printf("For individual command help, enter the command with \"-help\" flag in the end\n");
    printf("EXAMPLE:  nxclitool [COMMAND] -help\n");
    printf("\n");
}

sss_status_t nxclitool_get_uint32_from_hex_text(const char *key_id, uint32_t *slot)
{
    long long val = 0;
    if (strncmp(key_id, "0x", 2)) {
        LOG_E("Value in hex format is required here. Correct format is \"0x<ID>\"");
        return kStatus_SSS_Fail;
    }
    val = strtoll(key_id, NULL, 0);
    if (val < 0 || val > UINT32_MAX) {
        return kStatus_SSS_Fail;
    }
    *slot = (uint32_t)val;
    return kStatus_SSS_Success;
}

int nxclitool_get_crt_level(char *input, NX_CERTIFICATE_LEVEL_t *cert_level)
{
    if (0 == strcmp(input, "leaf")) {
        *cert_level = NX_CERTIFICATE_LEVEL_LEAF;
        return 0;
    }
    else if (0 == strcmp(input, "p1")) {
        *cert_level = NX_CERTIFICATE_LEVEL_P1;
        return 0;
    }
    else if (0 == strcmp(input, "p2")) {
        *cert_level = NX_CERTIFICATE_LEVEL_P2;
        return 0;
    }
    else if (0 == strcmp(input, "root")) {
        *cert_level = NX_CERTIFICATE_LEVEL_ROOT;
        return 0;
    }
    else {
        return 1;
    }
}

int nxclitool_get_comm_mode(char *input, Nx_CommMode_t *comm_mode)
{
    if (0 == strcmp(input, "plain")) {
        *comm_mode = Nx_CommMode_Plain;
        return 0;
    }
    else if (0 == strcmp(input, "mac")) {
        *comm_mode = Nx_CommMode_MAC;
        return 0;
    }
    else if (0 == strcmp(input, "full")) {
        *comm_mode = Nx_CommMode_FULL;
        return 0;
    }
    else if (0 == strcmp(input, "na")) {
        *comm_mode = Nx_CommMode_NA;
        return 0;
    }
    else {
        return 1;
    }
}

int nxclitool_get_access_cond(char *input, Nx_AccessCondition_t *acc_cond)
{
    uint32_t acc_cond_val = 0;
    sss_status_t status   = nxclitool_get_uint32_from_hex_text(input, &acc_cond_val);
    if (status != kStatus_SSS_Success) {
        return 1;
    }
    if (acc_cond_val > 0x0F) {
        LOG_E("Invalid access condition");
        return 1;
    }
    *acc_cond = (Nx_AccessCondition_t)acc_cond_val;
    return 0;
}

void nxclitool_do_session_close_and_cleanup(nxclitool_sss_boot_ctx_t *pboot_ctx, nx_connect_ctx_t *pconn_ctx)
{
    if (pboot_ctx != NULL) {
        if (&pboot_ctx->ks != NULL) {
            sss_key_store_context_free(&pboot_ctx->ks);
        }
        sss_session_close((&pboot_ctx->session));
    }

    /* Free the key objects generated in connection context during session open */
    if (pconn_ctx != NULL) {
        nx_auth_symm_static_ctx_t *static_ctx = &pconn_ctx->auth.ctx.symmAuth.static_ctx;
        nx_auth_symm_dynamic_ctx_t *dyn_ctx   = &pconn_ctx->auth.ctx.symmAuth.dyn_ctx;
        sss_host_key_object_free(&static_ctx->appKey);
        sss_host_key_object_free(&dyn_ctx->k_e2);
        sss_host_key_object_free(&dyn_ctx->k_m2);
    }
}

sss_status_t nxclitool_do_session_open(
    nxclitool_sss_boot_ctx_t *pboot_ctx, nx_connect_ctx_t *pconn_ctx, nx_auth_type_t auth_type)
{
    sss_status_t status             = kStatus_SSS_Fail;
    sss_connection_type_t conn_type = kSSS_ConnectionType_Plain;

    if (pconn_ctx->auth.authType != knx_AuthType_None) {
        conn_type = kSSS_ConnectionType_Encrypted;
        status    = nx_prepare_host_for_auth(&pboot_ctx->host_session, &pboot_ctx->host_ks, pconn_ctx);
        ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    }

    status = sss_session_open(&pboot_ctx->session, kType_SSS_SE_NX, 0, conn_type, pconn_ctx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_key_store_context_init(&pboot_ctx->ks, &pboot_ctx->session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    return status;
}

int nxclitool_perso_util_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint8_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint8_t *prvkeyIndex,
    size_t *privateKeyLen)
{
    size_t i      = 0;
    size_t taglen = 0;
    int tag       = 0;
    int ret       = -1;

    ENSURE_OR_GO_EXIT(input != NULL);
    ENSURE_OR_GO_EXIT(pubkeyIndex != NULL);
    ENSURE_OR_GO_EXIT(publicKeyLen != NULL);
    ENSURE_OR_GO_EXIT(prvkeyIndex != NULL);
    ENSURE_OR_GO_EXIT(privateKeyLen != NULL);

    for (;;) {
        ENSURE_OR_GO_EXIT(i < inLen);
        tag = input[i++];
        if (IS_VALID_TAG(tag)) {
            ENSURE_OR_GO_EXIT(i < inLen);
            taglen = input[i++];
            if (taglen == 0x81) {
                ENSURE_OR_GO_EXIT(i < inLen);
                taglen = input[i];
                i      = i + 1;
            }
            else if (taglen == 0x82) {
                ENSURE_OR_GO_EXIT(i < (inLen - 1));
                taglen = input[i] | input[i + 1] << 8;
                i      = i + 2;
            }

            if (taglen > inLen) {
                goto exit;
            }

            if (tag == ASN_TAG_OCTETSTRING) {
                ENSURE_OR_GO_EXIT((UINT_MAX - i) >= taglen);
                if (i + taglen == inLen) {
                    continue;
                }
                else {
                    *prvkeyIndex   = (uint8_t)i;
                    *privateKeyLen = taglen;
                }
            }

            if (tag == ASN_TAG_BITSTRING) {
                *pubkeyIndex  = (uint8_t)i;
                *publicKeyLen = taglen;
                ENSURE_OR_GO_EXIT(i < inLen);
                if (input[i] == 0x00 || input[i] == 0x01) {
                    ENSURE_OR_GO_EXIT((UINT8_MAX - 1) >= (*pubkeyIndex));
                    *pubkeyIndex  = *pubkeyIndex + 1;
                    *publicKeyLen = *publicKeyLen - 1;
                }
                break;
            }
            ENSURE_OR_GO_EXIT((UINT_MAX - i) >= taglen);
            if (i + taglen == inLen) {
                continue;
            }
            else {
                i = i + taglen;
            }
        }
        else {
            goto exit;
        }
    }

    ENSURE_OR_GO_EXIT((*pubkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT((UINT_MAX - (*pubkeyIndex)) >= (*publicKeyLen));
    ENSURE_OR_GO_EXIT(((*pubkeyIndex) + (*publicKeyLen)) <= inLen);
    ENSURE_OR_GO_EXIT((*prvkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT((UINT_MAX - (*prvkeyIndex)) >= (*privateKeyLen));
    ENSURE_OR_GO_EXIT(((*prvkeyIndex) + (*privateKeyLen)) <= inLen);
    ret = 0;

exit:
    return ret;
}

static sss_status_t nxclitool_provision_parse_keypair_get_private_key(
    uint8_t *keyPairBuf, size_t keyPairBufLen, uint8_t *privKeyBuf, size_t *privKeyBufLen)
{
    sss_status_t status = kStatus_SSS_Success;
    int ret             = -1;
    uint8_t publicIndex = 0, privateIndex = 0;
    size_t pubLen = 0, privLen = 0;

    ENSURE_OR_GO_EXIT(keyPairBuf != NULL);
    ENSURE_OR_GO_EXIT(privKeyBuf != NULL);
    ENSURE_OR_GO_EXIT(privKeyBufLen != NULL);

    ret = nxclitool_perso_util_asn1_get_ec_pair_key_index(
        keyPairBuf, keyPairBufLen, &publicIndex, &pubLen, &privateIndex, &privLen);
    if (ret == 0) {
        if (privLen <= 0) {
            LOG_E("The input certificate/key is not a valid keypair");
            status = kStatus_SSS_Fail;
        }
        ENSURE_OR_GO_EXIT(privateIndex < keyPairBufLen);
        memcpy(&privKeyBuf[0], &keyPairBuf[privateIndex], privLen);
        *privKeyBufLen = privLen;
    }
    else {
        LOG_E("The input certificate/key is not a valid keypair");
        status = kStatus_SSS_Fail;
    }

exit:
    return status;
}

int nxclitool_store_der_to_pem(FILE *fp, unsigned char *input, size_t *in_len, char *name, size_t name_len)
{
    int ret = -1;
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS

    char pem_begin[50]         = "-----BEGIN ";
    char pem_end[50]           = "-----END ";
    char tail[]                = "-----\n";
    unsigned char output[4096] = {0};
    size_t out_len             = sizeof(output);
    size_t olen                = 0;
    size_t bytes_written       = 0;

    if (name_len > 33) {
        return ret;
    }
    memcpy(&pem_begin[11], name, name_len - 1); // Copying name excluding the NULL character
    memcpy(&pem_begin[name_len - 1 + 11], tail, sizeof(tail));

    memcpy(&pem_end[9], name, name_len - 1); // Copying name excluding the NULL character
    memcpy(&pem_end[name_len - 1 + 9], tail, sizeof(tail));

    ret = mbedtls_pem_write_buffer((char *)pem_begin, (char *)pem_end, input, *in_len, output, out_len, &olen);
    if (ret != 0 || olen == 0) {
        LOG_E("mbedtls_pem_write_buffer() function failed!!");
        return ret;
    }
    bytes_written = fwrite(output, sizeof(unsigned char), olen - 1, fp);
    if (bytes_written != olen - 1) {
        LOG_E("Failed to write the PEM buffer to file!!");
        return -1;
    }

#elif SSS_HAVE_HOSTCRYPTO_OPENSSL

    const unsigned char *pinput = input;
    char hdr[]                  = {0};

    ret = PEM_write(fp, name, hdr, pinput, *in_len);
    if (ret <= 0) {
        LOG_E("PEM_write() function failed");
        ret = -1;
    }
    else {
        ret = 0;
    }
#endif
    return ret;
}

int nxclitool_convert_pem_to_der(FILE *fp, unsigned char *pucOutput, size_t *pxOlen, char *name)
{
    int lRet                                   = 1;
    char pemMarker[MAX_PEM_MARKER_LEN]         = "-----BEGIN ";
    size_t pemMarkerLen                        = 11;
    unsigned char pemBuf[MAX_CERT_BUF_LEN + 1] = {0};

    LOG_D("FN: %s", __FUNCTION__);

    strncpy(pemMarker + pemMarkerLen, name, MAX_PEM_MARKER_LEN - pemMarkerLen - 1);

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    const unsigned char *pucS1  = NULL;
    const unsigned char *pucS2  = NULL;
    const unsigned char *pucEnd = NULL;
    size_t xLen                 = 0;
    size_t xOtherLen            = 0;
    size_t pemBufLen            = sizeof(pemBuf);

    LOG_D("PEM Marker: %s", pemMarker);

    if (pemBufLen <= MAX_CERT_BUF_LEN) {
        LOG_E("Buffer size is not sufficient to hold the certificate/key string");
        return (-1);
    }

    xLen = fread(pemBuf, sizeof(char), MAX_CERT_BUF_LEN, fp);
    if (xLen == 0) {
        return (-1);
    }
    pucEnd = pemBuf + xLen;
    pucS1  = (unsigned char *)strstr((const char *)pemBuf, pemMarker);

    if (pucS1 == NULL) {
        LOG_D("pucS1 == NULL");
        return (-1);
    }

    pucS2 = (unsigned char *)strstr((const char *)pucS1, "-----END");

    if (pucS2 == NULL) {
        LOG_D("pucS2 == NULL");
        return (-1);
    }

    pucS1 += 25;

    while (pucS1 < pucEnd && *pucS1 != '-') {
        pucS1++;
    }

    while (pucS1 < pucEnd && *pucS1 == '-') {
        pucS1++;
    }

    if (pucS1 >= pucEnd) {
        LOG_D("pucS1 >= pucEnd");
        return (-1);
    }

    if (*pucS1 == '\r') {
        pucS1++;
    }

    if (*pucS1 == '\n') {
        pucS1++;
    }

    if ((pucS2 <= pucS1) || (pucS2 > pucEnd)) {
        LOG_D("(pucS2 <= pucS1) || (pucS2 > pucEnd)");
        return (-1);
    }

    LOG_D("FN: mbedtls_base64_decode");
    lRet = mbedtls_base64_decode(NULL, 0, &xOtherLen, (const unsigned char *)pucS1, pucS2 - pucS1);

    if (lRet == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        return (lRet);
    }

    if (xOtherLen > *pxOlen) {
        return (-1);
    }

    if ((lRet = mbedtls_base64_decode(pucOutput, xOtherLen, &xOtherLen, (const unsigned char *)pucS1, pucS2 - pucS1)) !=
        0) {
        return (lRet);
    }

    *pxOlen = xOtherLen;
    lRet    = 0;

#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    int pemReadStatus  = 0;
    char *pName        = (char *)pemMarker;
    char *header       = NULL;
    uint8_t *prvKeyDer = NULL;
    long prvKeyDerLen  = 0;
    long seekOffset    = 0;
    char *ptrMarker    = NULL;
    size_t xLen        = 0;

    // Search for required name in the file pinter
    xLen = fread(pemBuf, sizeof(char), MAX_CERT_BUF_LEN, fp);
    if (xLen == 0) {
        return (-1);
    }
    ptrMarker = strstr((const char *)pemBuf, pName);
    ENSURE_OR_GO_CLEANUP(ptrMarker != NULL);
    LOG_D("PEM Buf: %s", pemBuf);
    LOG_D("Marker Buf: %s", ptrMarker);
    seekOffset = (ptrMarker - (char *)pemBuf) / sizeof(char);
    LOG_D("Read from file offset: %d", seekOffset);

    fseek(fp, seekOffset, SEEK_SET);
    pemReadStatus = PEM_read(fp, &pName, &header, &prvKeyDer, &prvKeyDerLen);
    LOG_D("pemReadStatus = %d", pemReadStatus);
    LOG_D("name = %s", pName);
    LOG_D("prvKeyDerLen = %d", prvKeyDerLen);
    if (pemReadStatus != 1) {
        LOG_E("Error reading private key file!");
        lRet = -1;
        goto cleanup;
    }
    if (prvKeyDerLen < (32 /*private key length*/ + 7 /*header*/)) {
        lRet = -1;
        LOG_E("Buffer does not contain private key!");
        goto cleanup;
    }
    if (prvKeyDerLen > (long)*pxOlen) {
        lRet = -1;
        LOG_E("Insufficient buffer to hold the certificate/key");
        goto cleanup;
    }
    memcpy(pucOutput, prvKeyDer, prvKeyDerLen);
    *pxOlen = prvKeyDerLen;
    lRet    = 0;

cleanup:
    if (prvKeyDer != NULL) {
        OPENSSL_free(prvKeyDer);
    }
#endif
    return lRet;
}

// Returns: 0 for SUCCESS, 1 for FAILURE
int nxclitool_fetch_parameters(int argc,
    const char *argv[],
    int i, // Starting index to fetch arguments
    size_t *rng_bytes,
    uint32_t *repo_id,
    uint32_t *key_id,
    Nx_ECCurve_t *curve_type,
    NX_CERTIFICATE_LEVEL_t *cert_level,
    bool *is_pkcs7,
    Nx_CommMode_t *write_comm_mode,
    Nx_AccessCondition_t *write_access_cond,
    Nx_CommMode_t *read_comm_mode,
    Nx_AccessCondition_t *read_access_cond,
    Nx_CommMode_t *known_comm_mode,
    NXCLITOOL_KEY_TYPE_t *key_type,
    char file_in_path[],
    char file_out_path[],
    bool *file_out_flag,
    NXCLITOOL_OPERATION_t *operation)
{
    sss_status_t status         = kStatus_SSS_Fail;
    bool rng_bytes_flag         = (rng_bytes == NULL);
    bool repo_id_flag           = (repo_id == NULL);
    bool key_id_flag            = (key_id == NULL);
    bool curve_type_flag        = (curve_type == NULL);
    bool cert_level_flag        = (cert_level == NULL);
    bool is_pkcs7_flag          = (is_pkcs7 == NULL);
    bool write_comm_mode_flag   = (write_comm_mode == NULL);
    bool write_access_cond_flag = (write_access_cond == NULL);
    bool read_comm_mode_flag    = (read_comm_mode == NULL);
    bool read_access_cond_flag  = (read_access_cond == NULL);
    bool known_comm_mode_flag   = (known_comm_mode == NULL);
    bool key_type_flag          = (key_type == NULL);
    bool file_in_flag           = (file_in_path == NULL);
    bool operation_flag         = (operation == NULL);

    int temp_int_holder = 0;

    if (i >= argc) {
        LOG_E("No options provided. Check usage below");
        return 1;
    }

    while (i < argc) {
        if (0 == strcmp(argv[i], "-bytes")) {
            if (rng_bytes != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                rng_bytes_flag  = TRUE;
                temp_int_holder = atoi(argv[i]);
                if (temp_int_holder < 0) {
                    LOG_E("Number of bytes cannot be negative");
                    return 1;
                }
                *rng_bytes = (size_t)temp_int_holder;
                i++;
            }
            else {
                LOG_E("\"-bytes\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-curve")) {
            if (curve_type != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                curve_type_flag = TRUE;
                if (0 == strcmp(argv[i], "na")) {
                    *curve_type = Nx_ECCurve_NA;
                }
                else if (0 == strcmp(argv[i], "prime256v1")) {
                    *curve_type = Nx_ECCurve_NIST_P256;
                }
                else if (0 == strcmp(argv[i], "brainpoolP256r1")) {
                    *curve_type = Nx_ECCurve_Brainpool256;
                }
                else {
                    LOG_E("Invalid parameter for \"-curve\"");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-curve\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-repoid")) {
            if (repo_id != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                repo_id_flag = TRUE;
                status       = nxclitool_get_uint32_from_hex_text(argv[i], repo_id);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                i++;
            }
            else {
                LOG_E("\"-repoid\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-keyid")) {
            if (key_id != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                key_id_flag = TRUE;
                status      = nxclitool_get_uint32_from_hex_text(argv[i], key_id);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                i++;
            }
            else {
                LOG_E("\"-keyid\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-certlevel")) {
            if (cert_level != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                cert_level_flag = TRUE;
                if (nxclitool_get_crt_level((char *)argv[i], cert_level)) {
                    LOG_E("Invalid parameter for \"-certlevel\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-certlevel\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-certtype")) {
            if (is_pkcs7 != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                is_pkcs7_flag = TRUE;
                if (0 == strcmp(argv[i], "pkcs7")) {
                    *is_pkcs7 = TRUE;
                }
                else if (0 == strcmp(argv[i], "x509")) {
                    *is_pkcs7 = FALSE;
                }
                else {
                    LOG_E("Invalid parameter for \"-certtype\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-certtype\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-wcomm")) {
            if (write_comm_mode != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                write_comm_mode_flag = TRUE;
                if (nxclitool_get_comm_mode((char *)argv[i], write_comm_mode)) {
                    LOG_E("Invalid parameter for \"-wcomm\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-wcomm\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-waccess")) {
            if (write_access_cond != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                write_access_cond_flag = TRUE;
                if (nxclitool_get_access_cond((char *)argv[i], write_access_cond)) {
                    LOG_E("Invalid parameter for \"-waccess\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-waccess\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-rcomm")) {
            if (read_comm_mode != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                read_comm_mode_flag = TRUE;
                if (nxclitool_get_comm_mode((char *)argv[i], read_comm_mode)) {
                    LOG_E("Invalid parameter for \"-rcomm\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-rcomm\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-raccess")) {
            if (read_access_cond != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                read_access_cond_flag = TRUE;
                if (nxclitool_get_access_cond((char *)argv[i], read_access_cond)) {
                    LOG_E("Invalid parameter for \"-raccess\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-raccess\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-kcomm")) {
            if (known_comm_mode != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                known_comm_mode_flag = TRUE;
                if (nxclitool_get_comm_mode((char *)argv[i], known_comm_mode)) {
                    LOG_E("Invalid parameter for \"-kcomm\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-kcomm\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-keytype")) {
            if (key_type != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                key_type_flag = TRUE;
                if (0 == strcmp(argv[i], "leaf")) {
                    *key_type = NXCLITOOL_KEY_TYPE_LEAF;
                }
                else if (0 == strcmp(argv[i], "rootca")) {
                    *key_type = NXCLITOOL_KEY_TYPE_ROOT_CA;
                }
                else if (0 == strcmp(argv[i], "public")) {
                    *key_type = NXCLITOOL_KEY_TYPE_PUBLIC;
                }
                else if (0 == strcmp(argv[i], "private")) {
                    *key_type = NXCLITOOL_KEY_TYPE_PRIVATE;
                }
                else if (0 == strcmp(argv[i], "keypair")) {
                    *key_type = NXCLITOOL_KEY_TYPE_PAIR;
                }
                else {
                    LOG_E("Invalid parameter for \"-keytype\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-keytype\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-in")) {
            if (file_in_path != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                strcpy(file_in_path, argv[i]);
                file_in_flag = TRUE;
                i++;
            }
            else {
                LOG_E("\"-in\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-out")) {
            if (file_out_path != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                strcpy(file_out_path, argv[i]);
                *file_out_flag = TRUE;
                i++;
            }
            else {
                LOG_E("\"-out\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-enable")) {
            if (operation != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                operation_flag = TRUE;
                if (0 == strcmp(argv[i], "none")) {
                    *operation = NXCLITOOL_OPERATION_NONE;
                }
                else if (0 == strcmp(argv[i], "sign")) {
                    *operation = NXCLITOOL_OPERATION_SIGN;
                }
                else if (0 == strcmp(argv[i], "ecdh")) {
                    *operation = NXCLITOOL_OPERATION_ECDH;
                }
                else {
                    LOG_E("Invalid parameter for \"-enable\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-enable\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else {
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            LOG_W("Ignoring the unrecognised option \"%s\" for this command", argv[i]);
            i++;
        }
    }

    if (!(rng_bytes_flag && repo_id_flag && key_id_flag && curve_type_flag && cert_level_flag && is_pkcs7_flag &&
            write_comm_mode_flag && write_access_cond_flag && read_comm_mode_flag && read_access_cond_flag &&
            known_comm_mode_flag && file_in_flag && operation_flag)) {
        if (!rng_bytes_flag) {
            LOG_E("\"-bytes\" option is required for this operation. Refer usage for this command.");
        }
        if (!repo_id_flag) {
            LOG_E("\"-repoid\" option is required for this operation. Refer usage for this command.");
        }
        if (!key_id_flag) {
            LOG_E("\"-keyid\" option is required for this operation. Refer usage for this command.");
        }
        if (!curve_type_flag) {
            LOG_E("\"-curve\" option is required for this operation. Refer usage for this command.");
        }
        if (!cert_level_flag) {
            LOG_E("\"-certlevel\" option is required for this operation. Refer usage for this command.");
        }
        if (!is_pkcs7_flag) {
            LOG_E("\"-certtype\" option is required for this operation. Refer usage for this command.");
        }
        if (!write_comm_mode_flag) {
            LOG_E("\"-wcomm\" option is required for this operation. Refer usage for this command.");
        }
        if (!write_access_cond_flag) {
            LOG_E("\"-waccess\" option is required for this operation. Refer usage for this command.");
        }
        if (!read_comm_mode_flag) {
            LOG_E("\"-rcomm\" option is required for this operation. Refer usage for this command.");
        }
        if (!read_access_cond_flag) {
            LOG_E("\"-raccess\" option is required for this operation. Refer usage for this command.");
        }
        if (!known_comm_mode_flag) {
            LOG_E("\"-kcomm\" option is required for this operation. Refer usage for this command.");
        }
        if (!file_in_flag) {
            LOG_E("\"-in\" option is required for this operation. Refer usage for this command.");
        }
        if (!operation_flag) {
            LOG_E("\"-enable\" option is required for this operation. Refer usage for this command.");
        }
        return 1;
    }
    return 0;
}