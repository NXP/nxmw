/*
 *
 * Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "app_auth_device.h"
#include "fsl_sss_api.h"
#include "fsl_sss_nx_auth.h"
#include "sm_api.h"
#include "nx_const.h"
#include "nx_apdu.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "fsl_sss_nx_types.h"
#include "string.h"
#include "nx_reset.h"
#include "fsl_sss_nx_auth.h"


#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */


/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/**
 * @brief Shared connection context used across all session types.
 * @warning Only one session type should be active at a time.
 */
static nx_connect_ctx_t connectCtx = {0};

/** @brief Secure authenticator session representing the active authenticator device connection. */
static sss_session_t seSession = {0};

#if ((defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) || \
    (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
         (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)))
/** @brief Host-side cryptographic session (used for symmetric and SIGMA-I auth). */
static sss_session_t hostSession = {0};

/** @brief Host-side key store for managing authentication keys. */
static sss_key_store_t hostKeyStore = {0};
#endif

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */


/**
 * @brief Free key objects allocated during symmetric authentication session open.
 *
 * Releases the application key and the two session keys (encryption and MAC)
 * from both the static and dynamic parts of the symmetric auth context.
 *
 * @param[in] pConnectCtx  Pointer to the connection context containing the
 *                         symmetric authentication context to be freed.
 */
#if (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH))
static void ex_free_symm_auth_conn_ctx(nx_connect_ctx_t *pConnectCtx)
{
	nx_auth_symm_static_ctx_t *static_ctx = &pConnectCtx->auth.ctx.symmAuth.static_ctx;
	nx_auth_symm_dynamic_ctx_t *dyn_ctx   = &pConnectCtx->auth.ctx.symmAuth.dyn_ctx;

	/* Free static context: application key used for authentication */
	sss_host_key_object_free(&static_ctx->appKey);

	/* Free dynamic context: session encryption and MAC keys */
	sss_host_key_object_free(&dyn_ctx->k_e2);
	sss_host_key_object_free(&dyn_ctx->k_m2);
}
#endif

/**
 * @brief Free key objects allocated during SIGMA-I authentication session open.
 *
 * Releases all asymmetric and symmetric key objects from the SIGMA-I context,
 * including ephemeral keys, certificate keys, KDF keys, and session keys.
 *
 * @param[in] pConnectCtx  Pointer to the connection context containing the
 *                         SIGMA-I authentication context to be freed.
 */
#if ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
         (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)))

static void ex_free_sigma_i_auth_conn_ctx(nx_connect_ctx_t *pConnectCtx)
{
	nx_auth_sigma_ctx_t *pSigmaI = &pConnectCtx->auth.ctx.sigmai;

	/* Free static context: host and sec certificate/ephemeral key pairs */
	sss_host_key_object_free(&pSigmaI->static_ctx.leafCertKeypair);
	sss_host_key_object_free(&pSigmaI->static_ctx.ephemKeypair);
	sss_host_key_object_free(&pSigmaI->static_ctx.seEphemPubKey);
	sss_host_key_object_free(&pSigmaI->static_ctx.seLeafCertPubKey);

	/* Free dynamic context: KDF key and derived session encryption/MAC keys */
	sss_host_key_object_free(&pSigmaI->dyn_ctx.kdfCmac);
	sss_host_key_object_free(&pSigmaI->dyn_ctx.k_e1);
	sss_host_key_object_free(&pSigmaI->dyn_ctx.k_m1);
	sss_host_key_object_free(&pSigmaI->dyn_ctx.k_e2);
	sss_host_key_object_free(&pSigmaI->dyn_ctx.k_m2);
}
#endif

/**
 * @brief Initialize the common connection context fields shared by all session types.
 *
 * Resets the connection context and sets the connection type to T1oI2C
 * with no specific port name (uses default).
 *
 * @param[out] pConnectCtx  Pointer to the connection context to initialize.
 */
static void init_connect_ctx_defaults(nx_connect_ctx_t *pConnectCtx)
{
	memset(pConnectCtx, 0, sizeof(nx_connect_ctx_t));
	pConnectCtx->connType = kType_SE_Conn_Type_T1oI2C;
	pConnectCtx->portName = NULL;
}


/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */
void nx_auth_power_reset(void)
{
	AUTH_ARD_EVK_B_POWER_OFF();
	SDK_DelayAtLeastUs(5000U, CLOCK_GetCoreSysClkFreq());
	AUTH_ARD_EVK_B_POWER_ON();
	SDK_DelayAtLeastUs(5000U, CLOCK_GetCoreSysClkFreq());
}


#if (defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE))
sss_status_t nx_auth_plain_session_open(sss_nx_session_t **pSession, uint8_t skip_select_application)
{
	sss_status_t status = kStatus_SSS_Fail;

	/* Validate input parameter */
	if (pSession == NULL)
	{
		LOG_E("nx_auth_plain_session_open: pSession is NULL");
		goto cleanup;
	}

	/* Initialize connection context with default T1oI2C settings */
	init_connect_ctx_defaults(&connectCtx);
	connectCtx.skip_select_file = skip_select_application;	/*Skip Select NDEF Application command*/

	/* Open a plain (unauthenticated) session with the NX secure authenticator */
	status = sss_session_open(&seSession, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Plain, &connectCtx);
	ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

	*pSession = (sss_nx_session_t *)&seSession;

cleanup:
	return status;
}

sss_status_t nx_auth_plain_session_close(sss_nx_session_t *pSession)
{
	sss_status_t status = kStatus_SSS_Success;

	if (pSession != NULL)
	{
		status = sss_session_close((sss_session_t *)pSession);
	}

	return status;
}
#endif

#if (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH))
sss_status_t nx_auth_symmetric_session_open(sss_nx_session_t **pSession, uint8_t skip_select_application)
{
	sss_status_t status = kStatus_SSS_Fail;

	/* Validate input parameter */
	if (pSession == NULL)
	{
		LOG_E("nx_auth_symmetric_session_open: pSession is NULL");
		goto cleanup;
	}

	/* Initialize connection context with default T1oI2C settings */
	init_connect_ctx_defaults(&connectCtx);
	connectCtx.skip_select_file = skip_select_application;	/*Skip Select NDEF Application command*/

#if (defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2))
	nx_secure_symm_type_t secure_tunnel_type = knx_SecureSymmType_AES128_NTAG;
#elif (defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2))
	nx_secure_symm_type_t secure_tunnel_type = knx_SecureSymmType_AES256_NTAG;
#endif

	/* Configure symmetric authentication parameters:
	 * - Auth type : SYMM_AUTH (AES-based mutual authentication)
	 * - Cipher    : AES128_NTAG or AES256_NTAG
	 * - Key index : 0 (default application key slot)
	 * - Full auth : true (perform complete mutual authentication)
	 */
	status = nx_init_conn_context_symm_auth(
		&connectCtx,
		knx_AuthType_SYMM_AUTH,
		secure_tunnel_type,
		0,    /* Key index */
		true  /* Full authentication */
	);
	ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

	/* Initialize host-side cryptographic session and key store
	 * required for symmetric key operations during authentication */
	status = nx_prepare_host_for_auth(&hostSession, &hostKeyStore, &connectCtx);
	ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

	/* Open an encrypted session using symmetric authentication */
	status = sss_session_open(&seSession, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Encrypted, &connectCtx);
	ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

	*pSession = (sss_nx_session_t *)&seSession;

cleanup:
	return status;
}

sss_status_t nx_auth_symmetric_session_close(sss_nx_session_t *pSession)
{
	sss_status_t status = kStatus_SSS_Success;

	/* Close the secure authenticator session if active */
	if (pSession != NULL)
	{
		status = sss_session_close((sss_session_t *)pSession);
	}

	/* Release host-side resources regardless of SE session state */
	sss_host_session_close(&hostSession);
	sss_key_store_context_free(&hostKeyStore);

	/* Free symmetric authentication key objects from the connection context */
	ex_free_symm_auth_conn_ctx(&connectCtx);

	return status;
}
#endif

#if ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
         (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)))
sss_status_t nx_auth_sigma_i_session_open(sss_nx_session_t **pSession, uint8_t skip_select_application)
{
	sss_status_t status = kStatus_SSS_Fail;

	/* Validate input parameter */
	if (pSession == NULL)
	{
		LOG_E("nx_auth_sigma_i_session_open: pSession is NULL");
		goto cleanup;
	}

	/* Initialize connection context with default T1oI2C settings */
	init_connect_ctx_defaults(&connectCtx);
	connectCtx.skip_select_file = skip_select_application;	/*Skip Select NDEF Application command*/

#if (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER))
	nx_auth_type_t auth_type = knx_AuthType_SIGMA_I_Verifier;
#elif (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER))
	nx_auth_type_t auth_type = knx_AuthType_SIGMA_I_Prover;
#endif

#if (defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2))
	nx_secure_symm_type_t secure_tunnel_type = knx_SecureSymmType_AES128_NTAG;
#elif (defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2))
	nx_secure_symm_type_t secure_tunnel_type = knx_SecureSymmType_AES256_NTAG;
#endif

	/* Configure SIGMA-I authentication parameters:
	 * - Auth type       : AuthType_SIGMA_I_Prover or AuthType_SIGMA_I_Verifier
	 * - Symmetric cipher: AES-128 NTAG
	 * - Host key type   : EC NIST-P (for host leaf certificate keypair)
	 * - SE key type     : EC NIST-P (for SE leaf certificate public key)
	 * - Auth cache      : Enabled  (cache auth result to speed up reconnection)
	 * - Compression     : Disabled (no certificate compression)
	 * - Repo ID         : 0        (default certificate repository)
	 * - AC bitmap       : INVALID  (no specific access condition override)
	 */
	status = nx_init_conn_context_sigma_auth(
		&connectCtx,
		auth_type,
		secure_tunnel_type,
		kSSS_CipherType_EC_NIST_P,  /* Host leaf certificate key type */
		kSSS_CipherType_EC_NIST_P,  /* SE leaf certificate key type   */
		knx_AuthCache_Enabled,
		knx_AuthCompress_Disabled,
		0,                          /* Certificate repository ID */
		NX_AC_BITMAP_INVALID        /* Access condition bitmap   */
	);
	ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

	/* Initialize host-side cryptographic session and key store
	 * required for asymmetric key operations during SIGMA-I authentication */
	status = nx_prepare_host_for_auth(&hostSession, &hostKeyStore, &connectCtx);
	ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

	/* Open an encrypted session using SIGMA-I authentication */
	status = sss_session_open(&seSession, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Encrypted, &connectCtx);
	ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

	*pSession = (sss_nx_session_t *)&seSession;

cleanup:
	return status;
}

sss_status_t nx_auth_sigma_i_session_close(sss_nx_session_t *pSession)
{
	sss_status_t status = kStatus_SSS_Success;

	/* Close the secure authenticator session if active */
	if (pSession != NULL)
	{
		status = sss_session_close((sss_session_t *)pSession);
	}

	/* Release host-side resources regardless of SE session state */
	sss_host_session_close(&hostSession);
	sss_key_store_context_free(&hostKeyStore);

	/* Free all SIGMA-I authentication key objects from the connection context */
	ex_free_sigma_i_auth_conn_ctx(&connectCtx);

	return status;
}
#endif

