/*
 *
 * Copyright 2019-2020 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * ex_sss_boot_int.h:  *The purpose and scope of this file*
 *
 * Project:  SecureIoTMW-Debug@appboot-top-eclipse_x86
 *
 * $Date: Mar 10, 2019 $
 * $Author: ing05193 $
 * $Revision$
 */

#ifndef SSS_EX_SRC_EX_SSS_BOOT_INT_H_
#define SSS_EX_SRC_EX_SSS_BOOT_INT_H_

/* *****************************************************************************************************************
 *   Includes
 * ***************************************************************************************************************** */
#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"

/* *****************************************************************************************************************
 *   Function Prototypes
 * ***************************************************************************************************************** */
#if SSS_HAVE_NX_TYPE
sss_status_t ex_sss_boot_nx_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
sss_status_t ex_sss_boot_mbedtls_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
sss_status_t ex_sss_boot_openssl_open(ex_sss_boot_ctx_t *pCtx, const char *portName);
#endif

#endif /* SSS_EX_SRC_EX_SSS_BOOT_INT_H_ */
