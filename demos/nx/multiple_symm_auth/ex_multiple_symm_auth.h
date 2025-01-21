/* Copyright 2023 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_MULTIPLE_AUTH__
#define __EX_MULTIPLE_AUTH__

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

#if (SSS_HAVE_SECURE_TUNNELING_AES256_CCM)
#define SSS_EX_NX_SECURE_TUNNELING_MECH knx_SecureSymmType_AES256_CCM
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

#if (SSS_HAVE_AUTH_SYMM_APP_KEY_ID_0)
#define SSS_HAVE_AUTH_SYMM_APP_KEY 0
#endif

#if (SSS_HAVE_AUTH_SYMM_APP_KEY_ID_1)
#define SSS_HAVE_AUTH_SYMM_APP_KEY 1
#endif

#if (SSS_HAVE_AUTH_SYMM_APP_KEY_ID_2)
#define SSS_HAVE_AUTH_SYMM_APP_KEY 2
#endif

#if (SSS_HAVE_AUTH_SYMM_APP_KEY_ID_3)
#define SSS_HAVE_AUTH_SYMM_APP_KEY 3
#endif

#if (SSS_HAVE_AUTH_SYMM_APP_KEY_ID_4)
#define SSS_HAVE_AUTH_SYMM_APP_KEY 4
#endif

#endif // SSS_HAVE_NX_TYPE
#endif // __EX_MULTIPLE_AUTH__