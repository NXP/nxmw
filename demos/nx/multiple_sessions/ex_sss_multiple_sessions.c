/*
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
#include "platform.h"
#endif

#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "fsl_sss_nx_auth.h"
#include "fsl_sss_nx_auth_types.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define RANDOM_LEN_BYTES 32

int main(void)
{
    sss_status_t status  = kStatus_SSS_Fail;
    smStatus_t sm_status = SM_NOT_OK;

    sss_session_t plain_session   = {0};
    sss_session_t sigma_i_session = {0};

    nx_connect_ctx_t nx_open_params_plain = {0};
    nx_connect_ctx_t nx_open_params_sigma = {0};

    sss_session_t host_session         = {0};
    sss_cipher_type_t cert_curve_type  = kSSS_CipherType_EC_NIST_P;
    sss_cipher_type_t ephem_curve_type = kSSS_CipherType_EC_NIST_P;
    sss_key_store_t key_store          = {0};

    uint32_t free_memory               = 0;
    uint8_t rnd_data[RANDOM_LEN_BYTES] = {0};
    size_t rnd_data_len                = sizeof(rnd_data);
    sss_rng_context_t ctx_rng          = {0};

    nx_open_params_plain.connType = kType_SE_Conn_Type_T1oI2C;
    nx_open_params_plain.portName = NULL;

    /* Initialize the embedded platform */

#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
    platform_boot_direct();
    platform_init_hardware();
#endif

    /* Open a plain session */
    LOG_I("Open plain session \n");
    status = sss_session_open(&plain_session, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Plain, &nx_open_params_plain);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status)

    /* Run the get free memory call */
    sm_status = nx_FreeMem(&((sss_nx_session_t *)&plain_session)->s_ctx, &free_memory);
    ENSURE_OR_GO_CLEANUP(SM_OK == sm_status)

    LOG_I("Available free memory = %u", free_memory);

    LOG_I("Close plain session \n");
    sss_session_close(&plain_session);

    /* Set the parameters for SIGMA-I session */
    LOG_I("Init Host for Sigma-I session (AES128_NTAG) \n");
    status = nx_init_conn_context_sigma_auth(&nx_open_params_sigma,
        knx_AuthType_SIGMA_I_Verifier,
        knx_SecureSymmType_AES128_NTAG,
        cert_curve_type,
        ephem_curve_type,
        knx_AuthCache_Enabled,
        knx_AuthCompress_Disabled,
        0,
        NX_AC_BITMAP_INVALID);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    status = nx_prepare_host_for_auth(&host_session, &key_store, &nx_open_params_sigma);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    /* Open a SIGMA-I session */
    status =
        sss_session_open(&sigma_i_session, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Encrypted, &nx_open_params_sigma);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    /* Call a random number generation API over the SIGMA-I session */
    status = sss_rng_context_init(&ctx_rng, &sigma_i_session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_rng_get_random(&ctx_rng, rnd_data, rnd_data_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_I("Random bytes generated", rnd_data, rnd_data_len);

    LOG_I("Close sigma-i session \n");
    status = sss_session_close(&sigma_i_session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_host_session_close(&host_session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("gex_sss_multiple_sessions Example Success !!!...");
#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
        platform_success_indicator();
#endif
    }
    else {
        LOG_E("gex_sss_multiple_sessions Example Failed !!!...");
#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
        platform_failure_indicator();
#endif
    }
    if (ctx_rng.session != NULL) {
        sss_rng_context_free(&ctx_rng);
    }
    return 0;
}
