/*
*
* Copyright 2022-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef FSL_SSS_NX_AUTH_H
#define FSL_SSS_NX_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "nx_secure_msg_const.h"
#include "fsl_sss_nx_auth_types.h"
#include "nx_apdu_tlv.h"

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif
#include "fsl_sss_nx_auth_keys.h"

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

#if (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
    (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||     \
    (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) ||               \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))

/*
    Initialise authentication parameters for sigma auth.
*/
sss_status_t nx_init_conn_context_sigma_auth(nx_connect_ctx_t *nx_conn_ctx,
    nx_auth_type_t auth_type,
    nx_secure_symm_type_t secure_tunnel_type,
    sss_cipher_type_t host_cert_curve_type,
    sss_cipher_type_t host_ephem_curve_type,
    auth_cache_type_t cache_type,
    auth_compress_type_t compress_type,
    uint8_t se_cert_repo_id,
    uint16_t cert_ac_map);

/*
    Initialise authentication parameters for symmetric auth.
*/
sss_status_t nx_init_conn_context_symm_auth(nx_connect_ctx_t *nx_conn_ctx,
    nx_auth_type_t auth_type,
    nx_secure_symm_type_t secure_tunnel_type,
    uint8_t key_no,
    bool pcdcap2_flag);

/*
    Initialise/ Prepare host crypto for authentication set up.
*/
sss_status_t nx_prepare_host_for_auth(
    sss_session_t *host_session, sss_key_store_t *host_ks, nx_connect_ctx_t *nx_conn_ctx);

#endif

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif /* FSL_SSS_NX_AUTH_H */
