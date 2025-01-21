/*
 *
 * Copyright 2016-2020,2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _NX_PRINTF_H_
#define _NX_PRINTF_H_

#include <stdint.h>
#include <stdio.h>
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include "sm_types.h"

#if (defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)) || \
    (defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S))
    #include "platform.h"
#endif

#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
    /* Non-Embedded platforms */
	#define PRINTF printf
#endif
#endif // _NX_PRINTF_H_
