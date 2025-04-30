/* Copyright 2018, 2020, 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "nx_reset.h"
#include <stdio.h>

#include "fsl_gpio.h"
#include "sm_timer.h"
#include "sm_types.h"
#include "smComT1oI2C.h"
#include "nxLog_msg.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_NX_TYPE
void nx_ic_reset()
{
    if (SMCOM_OK != smComT1oI2C_ComReset(NULL)) {
        LOG_E("smComT1oI2C_ComReset failed");
        return;
    }
    sm_usleep(3000);
    return;
}
#endif
