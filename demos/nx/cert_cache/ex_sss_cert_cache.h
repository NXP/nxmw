/* Copyright 2023 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SSS_CERT_CACHE__
#define __EX_SSS_CERT_CACHE__

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

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

#if (SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P)
#define SSS_EX_HOST_CERT_CURVE_TYPE kSSS_CipherType_EC_NIST_P
#define SSS_EX_HOST_EPHEM_CURVE_TYPE kSSS_CipherType_EC_NIST_P
#elif (SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL)
#define SSS_EX_HOST_CERT_CURVE_TYPE kSSS_CipherType_EC_BRAINPOOL
#define SSS_EX_HOST_EPHEM_CURVE_TYPE kSSS_CipherType_EC_BRAINPOOL
#endif

#endif // SSS_HAVE_NX_TYPE
#endif // __EX_SSS_CERT_CACHE__