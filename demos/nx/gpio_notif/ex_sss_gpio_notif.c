/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "nxEnsure.h"
#include "nxLog_msg.h"
#include <string.h>
#include "ex_sss_boot.h"
#include "ex_sss_gpio_notif.h"
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM) || \
    defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) || defined(SSS_HAVE_HOST_RASPBIAN)
#include "nx_host_gpio.h"
#endif

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_gpio_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_gpio_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    sss_session_t *pPfSession            = NULL;
    sss_session_t hostSession            = {0};
    pPfSession                           = &hostSession;
    static nx_connect_ctx_t *pConnectCtx = NULL;
    static nx_connect_ctx_t nx_open_ctx  = {0};
    pConnectCtx                          = &nx_open_ctx;

    LOG_I("Successfully opened SIGMA-session");

    //Read PTB2
    U8 resp             = 0;
    uint8_t setInOutDir = NX_HOSTGPIOInput; //Set Input direction

#if SSS_HAVE_HOST_RASPBIAN
    U8 gpioPIN  = NX_HOST_RPI_INPUT_PIN_GPIO1; //PIN2
    U16 respLen = 0;
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)
    U8 gpioPIN = NX_HOSTGPIO_PTB2; //PIN2
#elif defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    U8 gpioPIN = NX_HOSTGPIO_PIO1_5; //PIN5
#endif
    gpio_pin_config_t config = {
        setInOutDir,
        0,
    };
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    U8 gpioPIN  = NX_HOSTGPIO_I01; //PIN2
    U16 respLen = 0;
#endif

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)

#if SSS_HAVE_HOST_RASPBIAN
    status = nx_host_GPIOInit(NULL, gpioPIN, setInOutDir);
    ENSURE_OR_GO_CLEANUP(status == TRUE);

    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)
    GPIO_PinInit(GPIOB, gpioPIN, &config);
    resp = (uint8_t)GPIO_PinRead(GPIOB, gpioPIN);
#elif defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    GPIO_PinInit(GPIO, NX_HOSTPGIO_PORT1, gpioPIN, &config);
    resp = (uint8_t)GPIO_PinRead(GPIO, NX_HOSTPGIO_PORT1, gpioPIN);
#endif
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    status = nx_host_GPIOInit(NULL, gpioPIN, setInOutDir);
    ENSURE_OR_GO_CLEANUP(status == TRUE);

    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif

    if (resp == NX_HOSTGPIO_Read_Low) {
        LOG_I("Read GPIONotif: Low");
    }
    else {
        LOG_I("Read GPIONotif: High");
    }
    LOG_U8_D(resp);

    pConnectCtx->connType = pCtx->nx_open_ctx.connType;
    pConnectCtx->portName = pCtx->nx_open_ctx.portName;

    status = sss_session_open(pPfSession, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Plain, pConnectCtx);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    LOG_I("Successfully opened Plain-session");

#if SSS_HAVE_HOST_RASPBIAN
    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)
    resp = (uint8_t)GPIO_PinRead(GPIOB, gpioPIN);
#elif defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    resp = (uint8_t)GPIO_PinRead(GPIO, NX_HOSTPGIO_PORT1, gpioPIN);
#endif
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif

    if (resp == NX_HOSTGPIO_Read_Low) {
        LOG_I("Read GPIONotif: Low");
    }
    else {
        LOG_I("Read GPIONotif: High");
    }
    LOG_U8_D(resp);

    status = sss_session_close(pPfSession);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

cleanup:

#if SSS_HAVE_HOST_RASPBIAN
    nx_host_GPIOClose(NULL, NX_HOST_RPI_INPUT_PIN_GPIO1);
#endif

    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_gpio_notif Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_gpio_notif Example Failed !!!...");
    }
    return status;
}