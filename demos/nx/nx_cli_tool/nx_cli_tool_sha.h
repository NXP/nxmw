/*
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/
#define SHA_INPUT_MAX_LEN 256
#define MD_LEN_BYTES 32

void nxclitool_show_command_help_sha()
{
    printf("\nUSAGE: nxclitool dgst-sha256 [OPTIONS]\n");
    printf("OPTIONS:\n");
    printf("  -in\t\tPath to the plain input data in txt format\n");
    printf("  -out\tWrite the message digest to a file on this path\n");
    printf("\n");
}

sss_status_t nxclitool_do_sha(nxclitool_sss_boot_ctx_t *pboot_ctx, char *in_file, char *out_file, bool out_file_flag)
{
    sss_status_t status              = kStatus_SSS_Fail;
    sss_digest_t ctx_digest          = {0};
    sss_algorithm_t algorithm        = kAlgorithm_SSS_SHA256;
    sss_mode_t mode                  = kMode_SSS_Digest;
    uint8_t input[SHA_INPUT_MAX_LEN] = {0};
    size_t inputLen                  = 0;
    uint8_t digest[MD_LEN_BYTES]     = {0};
    size_t digestLen                 = sizeof(digest);
    size_t bytes_written             = 0;
    FILE *input_fh                   = NULL;
    FILE *ref_fh                     = NULL;
    /* clang-format off */
    ENSURE_OR_GO_CLEANUP(NULL != pboot_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != in_file);
    ENSURE_OR_GO_CLEANUP(NULL != out_file);

    LOG_I("Using input at \"%s\"", in_file);
    if((input_fh = fopen(in_file, "rb")) != NULL) {
        inputLen = fread((char *)input, sizeof(char), SHA_INPUT_MAX_LEN, input_fh);
        if (inputLen > UINT8_MAX) {
            LOG_E("Input Data is more then 255 bytes in file");
            if (0 != fclose(input_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (0 != fclose(input_fh)) {
            LOG_E("Failed to close the file handle!");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
    else {
        LOG_E("Unable to open the input file at path \"%s\"", in_file);
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    LOG_I("Do Digest");
    LOG_MAU8_I("input", input, inputLen);
    status = sss_digest_context_init(&ctx_digest, &pboot_ctx->session, algorithm, mode);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = sss_digest_one_go(&ctx_digest, input, inputLen, digest, &digestLen);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    LOG_I("Digest successful!!!");
    LOG_MAU8_I("Sha256 :", digest, digestLen);

    if (out_file_flag) {
        LOG_I("Save the digest at file\"%s\"", out_file);
        ref_fh = fopen(out_file, "wb");
        if (NULL == ref_fh) {
            LOG_W("Unable to open a file to store the digest");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        bytes_written = fwrite((char *)digest, sizeof(unsigned char), digestLen, ref_fh);
        if (bytes_written != digestLen) {
            LOG_E("Failed to write the digest to file!!");
            if (0 != fclose(ref_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (0 != fclose(ref_fh)) {
            LOG_E("Failed to close the file handle!");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
    else {
        LOG_W("No output file path provided. digest has not be saved in file system");
    }

cleanup:
    
    if (kStatus_SSS_Success == status) {
        LOG_I("Message Digest Success !!!...");
    }
    else {
        LOG_E("Message Digest Failed !!!...");
    }
    if (ctx_digest.session != NULL) {
        sss_digest_context_free(&ctx_digest);
    }
    return status;
}