/*
*
* Copyright 2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <stdio.h>
#include <stdint.h>

#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
#include "fsl_debug_console.h"
#include "fsl_gpio.h"
#endif

#include "sm_timer.h"

int platform_boot_direct();
int platform_init_hardware();
void platform_init_network(const uint8_t *identifier);
void platform_success_indicator();
void platform_failure_indicator();
