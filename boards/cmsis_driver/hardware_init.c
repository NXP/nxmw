/*
 * Copyright 2025 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

/*${header:start}*/
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "app.h"
/*${header:end}*/

#if defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947 == 1)
uint32_t LPI2C2_GetFreq(void)
{
    return LPI2C_CLOCK_FREQUENCY;
}
uint32_t LPI2C3_GetFreq(void)
{
    return LPI2C3_CLOCK_FREQUENCY;
}
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153 == 1)
uint32_t LPI2C0_GetFreq(void)
{
    return LPI2C_CLOCK_FREQUENCY;
}
#endif
/* ${function:end} */
