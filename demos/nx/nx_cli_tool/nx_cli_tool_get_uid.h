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
    printf("\nUSAGE: nxclitool get-uid\n");
    printf("\n");
    printf("NOTE: get-uid command does not require any additional arguments.\n");
    printf("\n");
}

sss_status_t nxclitool_get_uid(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    smStatus_t sm_status       = SM_NOT_OK;
    sss_status_t status        = kStatus_SSS_Fail;
    sss_nx_session_t *pSession = NULL;

    uint8_t uidBuffer[10] = {0};
    size_t uidLen         = sizeof(uidBuffer);

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status = nx_GetCardUID(&((sss_nx_session_t *)pSession)->s_ctx, uidBuffer, &uidLen);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

    LOG_MAU8_I("Card UID", uidBuffer, uidLen);
    status = kStatus_SSS_Success;

cleanup:
    return status;
}