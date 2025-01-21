/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <string.h>
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "nx_enums.h"
#include "ex_sss_cert_cache.h"
#include "fsl_sss_nx_auth.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
static ex_sss_boot_ctx_t gex_sss_cert_cache_boot_ctx;

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define EX_SSS_BOOT_PCONTEXT (&gex_sss_cert_cache_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status      = kStatus_SSS_Fail;
    smStatus_t sm_status     = SM_NOT_OK;
    uint8_t leafCacheSize    = NX_CONF_CERT_LEAF_CACHE_SIZE_MAX;
    uint8_t intermCacheSize  = NX_CONF_CERT_INTERM_CACHE_SIZE_MAX;
    uint8_t featureSelection = (NX_CONF_CERT_HOSTCERT_SUPPORT << NX_CONF_CERT_HOSTCERT_SUPPORT_OFFSET) |
                               (NX_CONF_CERT_INTERNALCERT_SUPPORT << NX_CONF_CERT_INTERNALCERT_SUPPORT_OFFSET) |
                               (NX_CONF_CERT_SIGMA_I_CACHE_ENABLED);
    uint8_t acManageCertRepo   = (Nx_CommMode_Plain << NX_COMM_MODE_BIT_SHIFT) | Nx_AccessCondition_Free_Access;
    sss_nx_session_t *pSession = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Enable Secure Authenticator certificate cache");
    sm_status =
        nx_SetConfig_CertMgmt(&pSession->s_ctx, leafCacheSize, intermCacheSize, featureSelection, acManageCertRepo);
    ENSURE_OR_GO_CLEANUP(SM_OK == sm_status);

    status = sss_session_close(&pCtx->session);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    LOG_I("Close session 1");

    status = nx_init_conn_context_sigma_auth(&pCtx->nx_open_ctx,
        SSS_EX_NX_AUTH_MECH,
        SSS_EX_NX_SECURE_TUNNELING_MECH,
        SSS_EX_HOST_CERT_CURVE_TYPE,
        SSS_EX_HOST_EPHEM_CURVE_TYPE,
        knx_AuthCache_Enabled,
        knx_AuthCompress_Disabled,
        SSS_AUTH_ASYMM_CERT_REPO_ID,
        NX_AC_BITMAP_INVALID);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = nx_prepare_host_for_auth(&pCtx->host_session, &pCtx->host_ks, &pCtx->nx_open_ctx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_session_open(&pCtx->session, kType_SSS_SE_NX, 1, SSS_EX_CONNECTION_TYPE, &pCtx->nx_open_ctx);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Session 2 open succeed by certificate cache");

    status = sss_session_close(&pCtx->session);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);
    LOG_I("Close session 2");

cleanup:
    if ((kStatus_SSS_Success == status) && (SM_OK == sm_status)) {
        LOG_I("ex_sss_cert_cache Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_cert_cache Example Failed !!!...");
    }

    return status;
}
