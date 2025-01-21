/* Copyright 2018, 2020, 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "nx_reset.h"
#include <stdio.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_NX_TYPE
void nx_ic_reset()
{
    return;
}
#endif
