/*
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * platform_lpcxpresso55s.c:  Contains the code specific to lpcxpresso55s platform
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

#include "board.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "fsl_gpio.h"
#if defined(SSS_HAVE_HOSTCRYPTO_MBEDTLS) && (SSS_HAVE_HOSTCRYPTO_MBEDTLS)
#if defined(SSS_HAVE_MBEDTLS_2_X) && (SSS_HAVE_MBEDTLS_2_X)
//#include "ksdk_mbedtls.h"
#endif // SSS_HAVE_MBEDTLS_2_X
#endif // SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "nxLog_msg.h"
#include "sm_const.h"
#include "sm_timer.h"
#include "fsl_debug_console.h"

#if defined(SSS_HAVE_LOG_SEGGERRTT) && (SSS_HAVE_LOG_SEGGERRTT)
extern void nInit_segger_Log(void);
#endif

#define HAVE_KSDK_LED_APIS 1

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

void platform_boot_direct_impl()
{
    //    /* set BOD VBAT level to 1.65V */
    //     POWER_SetBodVbatLevel(kPOWER_BodVbatLevel1650mv, kPOWER_BodHystLevel50mv, false);

    CLOCK_SetClkDiv(kCLOCK_DivFlexcom4Clk, 1u);
    CLOCK_AttachClk(BOARD_DEBUG_UART_CLK_ATTACH);

    //     /* attach 12 MHz clock to FLEXCOMM8 (I2C master) */
    //     CLOCK_AttachClk(kFRO12M_to_FLEXCOMM4);

    //     /* attach main clock divide to FLEXCOMM2 */
    CLOCK_SetClkDiv(kCLOCK_DivFlexcom2Clk, 1u);
    CLOCK_AttachClk(kFRO12M_to_FLEXCOMM2);
    CLOCK_SetClkDiv(kCLOCK_DivFlexcom3Clk, 1u);
    CLOCK_AttachClk(kFRO12M_to_FLEXCOMM3);

    CLOCK_EnableClock(kCLOCK_InputMux);
    CLOCK_AttachClk(MUX_A(CM_ENETRMIICLKSEL, 0));
    CLOCK_EnableClock(kCLOCK_Enet);
    SYSCON0->PRESETCTRL2 = SYSCON_PRESETCTRL2_ENET_RST_MASK;
    SYSCON0->PRESETCTRL2 &= ~SYSCON_PRESETCTRL2_ENET_RST_MASK;

    //     /* reset FLEXCOMM for I2C */
    //     RESET_PeripheralReset(kFC4_RST_SHIFT_RSTn);

    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();

    LED_BLUE_INIT(1);
    LED_GREEN_INIT(1);
    LED_RED_INIT(1);

    LED_BLUE_ON();

    // #if defined(SSS_HAVE_LOG_SEGGERRTT) && (SSS_HAVE_LOG_SEGGERRTT)
    //     nInit_segger_Log();
    // #endif
}

int plaform_init_hardware_impl()
{
    int ret = 0;
    // #if defined(SSS_HAVE_MBEDTLS_2_X) && (SSS_HAVE_MBEDTLS_2_X)
    //     ret = 1;
    //     ret = CRYPTO_InitHardware();
    //     if (0 != ret) {
    //         goto exit;
    //     }
    // #endif
    // #if defined(FSL_FEATURE_SOC_SHA_COUNT) && (FSL_FEATURE_SOC_SHA_COUNT > 0)
    //     CLOCK_EnableClock(kCLOCK_Sha0);
    //     RESET_PeripheralReset(kSHA_RST_SHIFT_RSTn);
    // #endif /* SHA */

    sm_initSleep();

    //#if defined(SSS_HAVE_MBEDTLS_2_X) && (SSS_HAVE_MBEDTLS_2_X)
    //exit:
    //#endif
    return ret;
}

void platform_init_network_impl(const uint8_t *identifier)
{
    //int ret = 0;
    //LOG_I("platform_init_network mcxn947 not implemented");
}

void platform_success_indicator_impl()
{
    LED_BLUE_OFF();
    LED_RED_OFF();
    LED_GREEN_ON();
}

void platform_failure_indicator_impl()
{
    LED_BLUE_OFF();
    LED_RED_ON();
    LED_GREEN_OFF();
}
