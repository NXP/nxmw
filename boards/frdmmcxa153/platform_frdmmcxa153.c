/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * platform_frdmmcxa153.c:  Contains the code specific to mcxa153 platform
 *
 */

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#define HAVE_KSDK_LED_APIS 1

#include "board.h"
#include "fsl_gpio.h"
#include "pin_mux.h"
#include "sm_timer.h"
#include "clock_config.h"
#include "nxLog_msg.h"
#include "sm_const.h"
#include "fsl_debug_console.h"

#if defined(SSS_HAVE_LOG_SEGGERRTT) && (SSS_HAVE_LOG_SEGGERRTT)
extern void nInit_segger_Log(void);
#endif

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

#if defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)

static void BOARD_InitModuleClock(void)
{
    CLOCK_SetClockDiv(kCLOCK_DivLPI2C0, 1u);
    CLOCK_AttachClk(kFRO12M_to_LPI2C0);

    /* Attach 24M clock to I3C */
    CLOCK_SetClockDiv(kCLOCK_DivI3C0_FCLK, 4U);
    CLOCK_AttachClk(kFRO_HF_DIV_to_I3C0FCLK);
}

void platform_boot_direct_impl()
{
    BOARD_InitModuleClock();
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();
    sm_initSleep();

    LED_BLUE_INIT(1);
    LED_GREEN_INIT(1);
    LED_RED_INIT(1);

    LED_BLUE_ON();

#if defined(SSS_HAVE_LOG_SEGGERRTT) && (SSS_HAVE_LOG_SEGGERRTT)
    nInit_segger_Log();
#endif
}

int plaform_init_hardware_impl()
{
    return 0;
}

void platform_success_indicator_impl()
{
#if HAVE_KSDK_LED_APIS
    LED_BLUE_OFF();
    LED_RED_OFF();
    LED_GREEN_ON();
#endif // HAVE_KSDK_LED_APIS
}

void platform_failure_indicator_impl()
{
#if HAVE_KSDK_LED_APIS
    LED_BLUE_OFF();
    LED_RED_ON();
    LED_GREEN_OFF();
#endif // HAVE_KSDK_LED_APIS
}

#endif //#if defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
