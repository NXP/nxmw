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
    size_t bytes_written  = 0;

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
        getuid_fh = fopen(out_file, "ab");
        if (NULL == getuid_fh) {
            LOG_W("Unable to open a file to store the reference key");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        bytes_written = fwrite((char *)uidBuffer, sizeof(unsigned char), uidLen, getuid_fh);
        if (bytes_written != uidLen) {
            LOG_E("Failed to write the uid to file!!");
            if (0 != fclose(getuid_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        bytes_written = fwrite("\r\n", 1, 2, getuid_fh);
        if (bytes_written != 2) {
            LOG_E("Failed to write the end of line to file!!");
            if (0 != fclose(getuid_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (0 != fclose(getuid_fh)) {
            LOG_E("Failed to close the file handle!");
        }
    }
    else {
        LOG_W("No output file path provided. uid has not be saved in file system");
    }
    status = kStatus_SSS_Success;

cleanup:
    return status;
}