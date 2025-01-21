/* Copyright 2023 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SSS_GPIO__
#define __EX_SSS_GPIO__

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_NX_TYPE

#if (SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_ENABLED)
#define SSS_EX_NX_HOST_PK_CACHE_MECH knx_AuthCache_Enabled
#else
#define SSS_EX_NX_HOST_PK_CACHE_MECH knx_AuthCache_Disabled
#endif

#if (SSS_HAVE_HOST_CERT_COMPRESS_ENABLED)
#define SSS_EX_NX_HOST_CERT_COMRESS_MECH knx_AuthCompress_Enabled
#else
#define SSS_EX_NX_HOST_CERT_COMRESS_MECH knx_AuthCompress_Disabled
#endif

#if (SSS_HAVE_AUTH_ASYMM_HOST_CURVE_NIST_P)
#define SSS_EX_HOST_CERT_CURVE_TYPE kSSS_CipherType_EC_NIST_P
#define SSS_EX_HOST_EPHEM_CURVE_TYPE kSSS_CipherType_EC_NIST_P
#elif (SSS_HAVE_AUTH_ASYMM_HOST_CURVE_BRAINPOOL)
#define SSS_EX_HOST_CERT_CURVE_TYPE kSSS_CipherType_EC_BRAINPOOL
#define SSS_EX_HOST_EPHEM_CURVE_TYPE kSSS_CipherType_EC_BRAINPOOL
#endif

#endif // SSS_HAVE_NX_TYPE
#endif // __EX_SSS_GPIO__