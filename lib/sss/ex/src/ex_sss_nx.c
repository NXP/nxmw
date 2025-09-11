/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <stdio.h>
#include "ex_sss_boot.h"
#include "fsl_sss_nx_types.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "sm_const.h"
#include "fsl_sss_nx_auth.h"
#include "nxEnsure.h"
#include "ex_sss_boot_int.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

#if SSS_HAVE_NX_TYPE

#if (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)
#define SSS_EX_NX_AUTH_MECH knx_AuthType_SIGMA_I_Verifier
#define SSS_EX_CONNECTION_TYPE kSSS_ConnectionType_Encrypted
#endif

#if (SSS_HAVE_AUTH_SIGMA_I_PROVER)
#define SSS_EX_NX_AUTH_MECH knx_AuthType_SIGMA_I_Prover
#define SSS_EX_CONNECTION_TYPE kSSS_ConnectionType_Encrypted
#endif

#if (SSS_HAVE_AUTH_SYMM_AUTH)
#define SSS_EX_NX_AUTH_MECH knx_AuthType_SYMM_AUTH
#define SSS_EX_CONNECTION_TYPE kSSS_ConnectionType_Encrypted
#endif

#if (SSS_HAVE_AUTH_NONE)
#define SSS_EX_NX_AUTH_MECH knx_AuthType_None
#define SSS_EX_CONNECTION_TYPE kSSS_ConnectionType_Plain
#endif

#if (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_AES256_EV2)
#define SSS_EX_NX_SECURE_TUNNELING_MECH knx_SecureSymmType_AES128_AES256_NTAG
#endif

#if (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2)
#define SSS_EX_NX_SECURE_TUNNELING_MECH knx_SecureSymmType_AES128_NTAG
#endif

#if (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2)
#define SSS_EX_NX_SECURE_TUNNELING_MECH knx_SecureSymmType_AES256_NTAG
#endif

#if (SSS_HAVE_SECURE_TUNNELING_NONE)
#define SSS_EX_NX_SECURE_TUNNELING_MECH knx_SecureSymmType_None
#endif

#if (SSS_HAVE_HOST_CERT_COMPRESS_ENABLED)
#define SSS_EX_NX_HOST_CERT_COMRESS_MECH knx_AuthCompress_Enabled
#else
#define SSS_EX_NX_HOST_CERT_COMRESS_MECH knx_AuthCompress_Disabled
#endif

#if (SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_ENABLED)
#define SSS_EX_NX_HOST_PK_CACHE_MECH knx_AuthCache_Enabled
#else
#define SSS_EX_NX_HOST_PK_CACHE_MECH knx_AuthCache_Disabled
#endif

#if (SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P)
#define SSS_EX_HOST_CERT_CURVE_TYPE kSSS_CipherType_EC_NIST_P
#define SSS_EX_HOST_EPHEM_CURVE_TYPE kSSS_CipherType_EC_NIST_P
#elif (SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL)
#define SSS_EX_HOST_CERT_CURVE_TYPE kSSS_CipherType_EC_BRAINPOOL
#define SSS_EX_HOST_EPHEM_CURVE_TYPE kSSS_CipherType_EC_BRAINPOOL
#endif

#ifndef SSS_EX_NX_AUTH_MECH
#define SSS_EX_NX_AUTH_MECH knx_AuthType_None
#endif

#ifndef SSS_EX_CONNECTION_TYPE
#define SSS_EX_CONNECTION_TYPE kSSS_ConnectionType_Plain
#endif

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

sss_status_t ex_sss_boot_nx_open(ex_sss_boot_ctx_t *pCtx, const char *portName)
{
    sss_status_t status           = kStatus_SSS_Fail;
    nx_connect_ctx_t *pConnectCtx = NULL;
    sss_session_t *pPfSession     = NULL;

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    pPfSession  = &pCtx->session;
    pConnectCtx = &pCtx->nx_open_ctx;

#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    if (ex_sss_boot_isSerialPortName(portName)) {
        pConnectCtx->connType = kType_SE_Conn_Type_VCOM;
        pConnectCtx->portName = portName;
    }
#endif

#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    pConnectCtx->connType = kType_SE_Conn_Type_T1oI2C;
    pConnectCtx->portName = portName;
#endif

#if defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC)
    pConnectCtx->connType = kType_SE_Conn_Type_PCSC;
    pConnectCtx->portName = portName;
#endif

#if defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM)
    pConnectCtx->connType = kType_SE_Conn_Type_JRCP_V1_AM;
    pConnectCtx->portName = portName;
#endif

#if SSS_HAVE_HOSTCRYPTO_ANY
    pConnectCtx->auth.authType = SSS_EX_NX_AUTH_MECH;

    if ((pConnectCtx->auth.authType == knx_AuthType_SIGMA_I_Verifier) ||
        (pConnectCtx->auth.authType == knx_AuthType_SIGMA_I_Prover)) {
#if (SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER || SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        status = nx_init_conn_context_sigma_auth(pConnectCtx,
            SSS_EX_NX_AUTH_MECH,
            SSS_EX_NX_SECURE_TUNNELING_MECH,
            SSS_EX_HOST_CERT_CURVE_TYPE,
            SSS_EX_HOST_EPHEM_CURVE_TYPE,
            SSS_EX_NX_HOST_PK_CACHE_MECH,
            SSS_EX_NX_HOST_CERT_COMRESS_MECH,
            SSS_AUTH_ASYMM_CERT_REPO_ID,
            NX_AC_BITMAP_INVALID);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = nx_prepare_host_for_auth(&pCtx->host_session, &pCtx->host_ks, pConnectCtx);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
#else
        LOG_E("Wrong Authentication option selected. Rebuild the library with correct AUTH option");
        return kStatus_SSS_Fail;
#endif //#if (SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER || SSS_HAVE_ALL_AUTH_CODE_ENABLED)
    }
    else if (pConnectCtx->auth.authType == knx_AuthType_SYMM_AUTH) {
#if (SSS_HAVE_AUTH_SYMM_AUTH || SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        status = nx_init_conn_context_symm_auth(
            pConnectCtx, SSS_EX_NX_AUTH_MECH, SSS_EX_NX_SECURE_TUNNELING_MECH, SSS_HAVE_AUTH_SYMM_APP_KEY_ID, false);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = nx_prepare_host_for_auth(&pCtx->host_session, &pCtx->host_ks, pConnectCtx);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
#else
        LOG_E("Wrong Authentication option selected. Rebuild the library with correct AUTH option");
        return kStatus_SSS_Fail;
#endif // if (SSS_HAVE_AUTH_SYMM_AUTH || SSS_HAVE_ALL_AUTH_CODE_ENABLED)
    }
    else if (pConnectCtx->auth.authType == knx_AuthType_None) {
        /*Do Nothing*/
    }
    else {
        LOG_E("Invalid auth type");
        goto exit;
    }
#endif // SSS_HAVE_HOSTCRYPTO_ANY

    status = sss_session_open(pPfSession, kType_SSS_SE_NX, 0, SSS_EX_CONNECTION_TYPE, pConnectCtx);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

exit:
    return status;
}

#endif /* SSS_HAVE_NX_TYPE */
