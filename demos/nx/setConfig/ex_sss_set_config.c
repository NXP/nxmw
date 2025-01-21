/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include <string.h>
#include "nx_apdu.h"
#include "nx_enums.h"
#include "ex_sss_set_config.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
// set macro "SET_CONFIG_GPIO_NOTIFY_ENABLE 1" and configure IC for ex_sss_gpio_nofic on K64F.
#define SET_CONFIG_GPIO_NOTIFY_ENABLE 0
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_set_config_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_set_config_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    sss_nx_session_t *pSession = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    Nx_gpio_config_t gpioConfig = {0};
    gpioConfig.gpio1Mode        = Nx_GPIOMgmtCfg_GPIOMode_Output;
    gpioConfig.gpio2Mode        = Nx_GPIOMgmtCfg_GPIOMode_Input;
    gpioConfig.acManage         = (Nx_CommMode_FULL << NX_COMM_MODE_BIT_SHIFT) | Nx_AccessCondition_Auth_Required_0x0;
    gpioConfig.acRead           = (Nx_CommMode_FULL << NX_COMM_MODE_BIT_SHIFT) | Nx_AccessCondition_Auth_Required_0x0;
    gpioConfig.gpio1InputCfg    = Nx_GPIOPadCfg_InputCfg_HighImpedance;
    gpioConfig.gpio1OutputCfg   = Nx_GPIOPadCfg_OutputCfg_GPIO_Low_Speed_1;

#if SET_CONFIG_GPIO_NOTIFY_ENABLE
    gpioConfig.gpio1OutputNotif = Nx_GPIOMgmtCfg_GPIONotif_Auth;
#endif
    gpioConfig.gpio2OutputCfg     = Nx_GPIOPadCfg_OutputCfg_Output_disabled;
    gpioConfig.gpio2Supply1v1n1v2 = false;

    LOG_I("Running Set Configuration Example ex_sss_set_config.c");
    LOG_I("Set GPIO1 to output and GPIO2 to input.");
    LOG_I("Set ManageGPIO access condition to full protection and access condition 1.");

    sm_status = nx_SetConfig_GPIOMgmt(&((sss_nx_session_t *)pSession)->s_ctx, gpioConfig);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

#if SET_CONFIG_WATCHDOG_TIMER_ENABLE

    uint8_t HWDTValue  = SET_CONFIG_WATCHDOG_TIMER_HWDTVALUE;
    uint8_t AWDT1Value = SET_CONFIG_WATCHDOG_TIMER_AWDT1VALUE;
    uint8_t AWDT2Value = SET_CONFIG_WATCHDOG_TIMER_AWDT2VALUE;

    sm_status =
        nx_SetConfig_WatchdogTimerMgmt(&((sss_nx_session_t *)pSession)->s_ctx, HWDTValue, AWDT1Value, AWDT2Value);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
#endif

    LOG_I("Set Configuration successful !!!");
cleanup:
    if (SM_OK == sm_status) {
        status = kStatus_SSS_Success;
        LOG_I("ex_sss_set_config Example Success !!!...");
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("ex_sss_set_config Example Failed !!!...");
    }

    return status;
}
