/*
 *
 * Copyright 2023-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * ex_sss_boot.c:  *The purpose and scope of this file*
 */
/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */

#ifdef __cplusplus
extern "C" {
#endif

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "ex_sss_boot.h"

#include <string.h>

#include "ex_sss_boot_int.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "stdio.h"
#if SSS_HAVE_NX_TYPE
#include "nx_apdu.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

sss_status_t ex_sss_boot_open(ex_sss_boot_ctx_t *pCtx, const char *portName)
{
    sss_status_t status = kStatus_SSS_Fail;

#if SSS_HAVE_NX_TYPE
    status = ex_sss_boot_nx_open(pCtx, portName);
#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
    status = ex_sss_boot_mbedtls_open(pCtx, portName);
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    status = ex_sss_boot_openssl_open(pCtx, portName);
#endif
    return status;
}

sss_status_t ex_sss_key_store_and_object_init(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)

    status = sss_key_store_context_init(&pCtx->ks, &pCtx->session);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_store_context_init Failed...");
        goto cleanup;
    }

    status = sss_key_store_allocate(&pCtx->ks, __LINE__);
    if (status != kStatus_SSS_Success) {
        LOG_E(" sss_key_store_allocate Failed...");
        goto cleanup;
    }

cleanup:
    return status;
}

#if ((SSS_HAVE_HOSTCRYPTO_ANY) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER || \
                                      SSS_HAVE_AUTH_SYMM_AUTH || SSS_HAVE_ALL_AUTH_CODE_ENABLED))
static void free_auth_objects(nx_connect_ctx_t *pConnectCtx)
{
    if (NULL == pConnectCtx) {
        LOG_E("No context to free");
        goto exit;
    }
    if (pConnectCtx->auth.authType == knx_AuthType_SIGMA_I_Verifier ||
        pConnectCtx->auth.authType == knx_AuthType_SIGMA_I_Prover) {
        nx_auth_sigma_ctx_t *pSigmaI = &pConnectCtx->auth.ctx.sigmai;
        sss_host_key_object_free(&pSigmaI->static_ctx.leafCertKeypair);
        sss_host_key_object_free(&pSigmaI->static_ctx.ephemKeypair);
        sss_host_key_object_free(&pSigmaI->static_ctx.seEphemPubKey);
        sss_host_key_object_free(&pSigmaI->static_ctx.seLeafCertPubKey);
        sss_host_key_object_free(&pSigmaI->dyn_ctx.kdfCmac);
        sss_host_key_object_free(&pSigmaI->dyn_ctx.k_e1);
        sss_host_key_object_free(&pSigmaI->dyn_ctx.k_m1);
        sss_host_key_object_free(&pSigmaI->dyn_ctx.k_e2);
        sss_host_key_object_free(&pSigmaI->dyn_ctx.k_m2);
    }
    else if (pConnectCtx->auth.authType == knx_AuthType_SYMM_AUTH) {
        nx_auth_symm_static_ctx_t *static_ctx = &pConnectCtx->auth.ctx.symmAuth.static_ctx;
        nx_auth_symm_dynamic_ctx_t *dyn_ctx   = &pConnectCtx->auth.ctx.symmAuth.dyn_ctx;
        sss_host_key_object_free(&static_ctx->appKey);
        sss_host_key_object_free(&dyn_ctx->k_e2);
        sss_host_key_object_free(&dyn_ctx->k_m2);
    }

    memset(pConnectCtx, 0, sizeof(*pConnectCtx));

exit:
    return;
}
#endif //SSS_HAVE_HOSTCRYPTO_ANY && (either of one authentication)

void ex_sss_session_close(ex_sss_boot_ctx_t *pCtx)
{
    if (NULL == pCtx) {
        LOG_E("No context to free");
        goto exit;
    }
    if (pCtx->session.subsystem != kType_SSS_SubSystem_NONE) {
        sss_session_close(&pCtx->session);
    }

#if SSS_HAVE_NX_TYPE
#if ((SSS_HAVE_HOSTCRYPTO_ANY) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER || \
                                      SSS_HAVE_AUTH_SYMM_AUTH || SSS_HAVE_ALL_AUTH_CODE_ENABLED))
    nx_connect_ctx_t *pConnectCtx = &pCtx->nx_open_ctx;
    free_auth_objects(pConnectCtx);
#endif //SSS_HAVE_HOSTCRYPTO_ANY && (either of one authentication)

#if SSS_HAVE_HOSTCRYPTO_ANY
    if (pCtx->host_ks.session != NULL) {
        sss_host_key_store_context_free(&pCtx->host_ks);
    }
    if (pCtx->host_session.subsystem != kType_SSS_SubSystem_NONE) {
        sss_host_session_close(&pCtx->host_session);
    }
#endif // SSS_HAVE_HOSTCRYPTO_ANY
#endif

    if (pCtx->ks.session != NULL) {
        sss_key_store_context_free(&pCtx->ks);
    }
exit:
    return;
}

#if SSS_HAVE_HOSTCRYPTO_ANY
sss_status_t ex_sss_boot_open_host_session(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
    if (NULL == pCtx) {
        LOG_E("No context to open session");
        goto exit;
    }

#if SSS_HAVE_NX_TYPE
    if (pCtx->host_ks.session == NULL) {
        status = sss_session_open(&pCtx->host_session, kType_SSS_Software, 0, kSSS_ConnectionType_Plain, NULL);
        if (kStatus_SSS_Success != status) {
            LOG_E("Failed to open mbedtls Session");
            return status;
        }

        status = sss_key_store_context_init(&pCtx->host_ks, &pCtx->host_session);
        if (kStatus_SSS_Success != status) {
            LOG_E("sss_key_store_context_init failed");
            return status;
        }
        status = sss_key_store_allocate(&pCtx->host_ks, __LINE__);
        if (kStatus_SSS_Success != status) {
            LOG_E("sss_key_store_allocate failed");
            return status;
        }
    }
    else {
        /* when NX type and authentication method(e.g., Sigma-I or symmetric) are selected,
         * the host session is already opened in the NX Prepare Host API.
         */
        status = kStatus_SSS_Success;
        goto exit;
    }
#else
    /* For host only builds , main session & key store are same as host */
    LOG_W("Host session is not opened when no NX Type is selected \n");
    status             = kStatus_SSS_Success;
    pCtx->host_ks      = pCtx->ks;
    pCtx->host_session = pCtx->host_session;
#endif
exit:
    return status;
}
#endif // SSS_HAVE_HOSTCRYPTO_ANY

#ifdef __cplusplus
}
#endif
