/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#include <nx_apdu.h>
#include <fsl_sss_nx_auth_types.h>
#include <fsl_sss_util_asn1_der.h>
#include <fsl_sss_nx_types.h>

void nxclitool_show_command_help_get_uid()
{
    printf("\nUSAGE: nxclitool get-uid [OPTIONS]\n");
    printf("OPTIONS:\n");
    printf("  -out\t\tWrite the uid to a file on this path\n");
    printf("\n");
}

sss_status_t nxclitool_get_uid(
    int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx, char *out_file, bool out_file_flag)
{
    smStatus_t sm_status       = SM_NOT_OK;
    sss_status_t status        = kStatus_SSS_Fail;
    sss_nx_session_t *pSession = NULL;

    uint8_t uidBuffer[10] = {0};
    size_t uidLen         = sizeof(uidBuffer);
    FILE *getuid_fh       = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status = nx_GetCardUID(&((sss_nx_session_t *)pSession)->s_ctx, uidBuffer, &uidLen);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

#if defined(SSS_HAVE_LOG_SILENT) && (SSS_HAVE_LOG_SILENT)
    for (uint8_t i = 0; i < uidLen; i++) {
        printf("%x", uidBuffer[i]);
    }
#else
    LOG_MAU8_I("Card UID", uidBuffer, uidLen);
#endif
    if (out_file_flag) {
        getuid_fh = fopen(out_file, "a");
        if (NULL == getuid_fh) {
            LOG_W("Unable to open a file to store the uid");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        // Write UID in format: 0x<hex>; (e.g., 0x0465711BF72390;)
        if (0 > fprintf(getuid_fh, "0x")) {
            LOG_E("Failed to write opening quote in file handle!");
            if (0 != fclose(getuid_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        for (size_t i = 0; i < uidLen; i++) {
            if (0 > fprintf(getuid_fh, "%02X", uidBuffer[i])) {
                LOG_E("Failed to write uid in file handle!");
                if (0 != fclose(getuid_fh)) {
                    LOG_E("Failed to close the file handle!");
                }
                status = kStatus_SSS_Fail;
                goto cleanup;
            }
        }

        if (0 > fprintf(getuid_fh, ";")) {
            LOG_E("Failed to write closing quote and comma in file handle!");
            if (0 != fclose(getuid_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (0 != fclose(getuid_fh)) {
            LOG_E("Failed to close the file handle!");
            status = kStatus_SSS_Fail;
        }
    }
    else {
        LOG_W("No output file path provided. uid has not be saved in file system");
    }
    status = kStatus_SSS_Success;

cleanup:
    return status;
}