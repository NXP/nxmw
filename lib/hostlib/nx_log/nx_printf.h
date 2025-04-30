/*
 *
 * Copyright 2016-2020,2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _NX_PRINTF_H_
#define _NX_PRINTF_H_

#include <stdint.h>
#include <stdio.h>
#include "sm_types.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
#include "platform.h"
#else
/* Non-Embedded platforms */
#define PRINTF printf
#endif // SSS_HAVE_HOST_EMBEDDED

#endif //_NX_PRINTF_H_