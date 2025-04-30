/*
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "fsl_sss_nx_auth_types.h"

sss_status_t nx_provision_create_se_repository(
    ex_sss_boot_ctx_t *pCtx, uint8_t repoID, uint8_t privateKeyId, uint16_t repoSize)
{
    sss_status_t status         = kStatus_SSS_Fail;
    smStatus_t sm_status        = SM_NOT_OK;
    Nx_CommMode_t writeCommMode = Nx_CommMode_Plain;
    uint8_t writeAccessCond     = Nx_AccessCondition_Free_Access;
    Nx_CommMode_t readCommMode  = Nx_CommMode_Plain;
    uint8_t readAccessCond      = Nx_AccessCondition_Free_Access;
    sss_nx_session_t *pSession  = NULL;

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    pSession = (sss_nx_session_t *)&pCtx->session;

    writeCommMode   = Nx_CommMode_FULL;
    readCommMode    = Nx_CommMode_FULL;
    writeAccessCond = Nx_AccessCondition_Auth_Required_0x0;
    readAccessCond  = Nx_AccessCondition_Auth_Required_0x0;

    sm_status = nx_ManageCertRepo_CreateCertRepo(&pSession->s_ctx,
        repoID,
        privateKeyId,
        repoSize,
        writeCommMode,
        writeAccessCond,
        readCommMode,
        readAccessCond,
        Nx_CommMode_NA);

    if (sm_status != SM_OK) {
        LOG_E("nx_ManageCertRepo_CreateCertRepo Failed");
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nx_provision_load2se_uncompressed_cert(
    ex_sss_boot_ctx_t *pCtx, NX_CERTIFICATE_LEVEL_t certLevel, uint8_t repoID, uint8_t *certBuf, size_t certBufLen)
{
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    int tlvRet                 = 0;
    sss_nx_session_t *pSession = NULL;
    uint8_t taggedCert[1024]   = {0};
    size_t taggedCertLen       = 0;
    uint8_t *pCert             = NULL;

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    pSession = (sss_nx_session_t *)&pCtx->session;

    if (certBuf == NULL) {
        goto exit;
    }

    // 7F 21 <uncompressed cert>
    taggedCertLen = 0;
    taggedCert[0] = 0x7F;
    pCert         = &taggedCert[1];
    tlvRet        = TLVSET_u8buf(
        "cert", &pCert, &taggedCertLen, NX_TAG_UNCOMPRESSED_CERT, certBuf, certBufLen, sizeof(taggedCert) - 1);
    if (0 != tlvRet) {
        goto exit;
    }

    if (taggedCertLen > (UINT16_MAX - 1)) {
        goto exit;
    }

    sm_status = nx_ManageCertRepo_LoadCert(
        &pSession->s_ctx, repoID, certLevel, taggedCert, (uint16_t)(taggedCertLen + 1), Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        LOG_E("Load certificate Failed");
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t nx_provision_load2se_cert_mapping(ex_sss_boot_ctx_t *pCtx,
    uint8_t repoID,
    NX_CERTIFICATE_LEVEL_t certLevel,
    uint8_t *certMappingBuf,
    size_t certMappingBufLen)
{
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    sss_nx_session_t *pSession = NULL;

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    ENSURE_OR_GO_EXIT(certMappingBuf != NULL);
    ENSURE_OR_GO_EXIT(certMappingBufLen <= UINT16_MAX);
    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status = nx_ManageCertRepo_LoadCertMapping(
        &pSession->s_ctx, repoID, certLevel, certMappingBuf, (uint16_t)certMappingBufLen, Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        LOG_E("Load certificate template Failed");
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nx_provision_activate_se_cert_repo(ex_sss_boot_ctx_t *pCtx, uint8_t repoID)
{
    sss_status_t status        = kStatus_SSS_Fail;
    sss_nx_session_t *pSession = NULL;
    smStatus_t sm_status       = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status = nx_ManageCertRepo_ActivateRepo(&pSession->s_ctx, repoID, Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        LOG_E("Activate repository Failed");
        goto exit;
    }

    status = kStatus_SSS_Success;

exit:

    return status;
}
