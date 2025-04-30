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
#include "nx_host_gpio.h"
#include "nx_apdu.h"
#include "nx_enums.h"
#if defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED)
#include "board.h"
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
    sss_status_t status               = kStatus_SSS_Fail;
    smStatus_t sm_status              = SM_NOT_OK;
    sss_nx_session_t *pSession        = NULL;
    Nx_GPIONumber_t gpioNo            = Nx_GPIONo_1;
    Nx_GPIO_OutputCtl_t gpioOperation = Nx_GPIOOutput_Clear;

    Nx_GPIO_Status_t inputStatus                   = Nx_GPIO_STATUS_INVALID;
    Nx_GPIO_Status_t tagTamperPermStatus           = Nx_GPIO_STATUS_INVALID;
    Nx_GPIO_Status_t gpio1CurrentOrTTCurrentStatus = Nx_GPIO_STATUS_INVALID;
    Nx_GPIO_Status_t gpio2CurrentStatus            = Nx_GPIO_STATUS_INVALID;

    U8 resp = 0;

#if SSS_HAVE_HOST_RASPBIAN
    U8 gpioPIN          = NX_HOST_RPI_INPUT_PIN_GPIO1; //PIN2
    uint8_t gpiostatus  = FALSE;
    U16 respLen         = 0;
    uint8_t setInOutDir = NX_HOSTGPIOInput; //Set Input direction

#elif (defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)) || \
    (defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)) // Other MCU (K64F)

    uint8_t setInOutDir      = NX_HOSTGPIOInput; //Set Input direction
    gpio_pin_config_t config = {setInOutDir, 0};
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    U8 gpioPIN               = BOARD_PIO1_5_GPIO_PIN; //PIN5
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
    U8 gpioPIN = BOARD_PIO0_25_GPIO_PIN; //PIN25
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
    U8 gpioPIN = BOARD_P2_12_GPIO_PIN; //PIN12
#endif

#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    U8 gpioPIN          = NX_HOSTGPIO_I01;
    U16 respLen         = 0;
    uint8_t setInOutDir = NX_HOSTGPIOInput; //Set Input direction
#endif

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    // Set gpio1 output clear
    LOG_I("Clear GPIO1.");
    sm_status = nx_ManageGPIO_Output(
        &((sss_nx_session_t *)pSession)->s_ctx, gpioNo, (uint8_t)gpioOperation, NULL, 0, Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

#if SSS_HAVE_HOST_RASPBIAN
    gpioPIN    = NX_HOST_RPI_INPUT_PIN_GPIO1;
    gpiostatus = nx_host_GPIOInit(NULL, gpioPIN, setInOutDir);
    ENSURE_OR_GO_CLEANUP(gpiostatus == TRUE);

    gpiostatus = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(gpiostatus == TRUE);
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));

#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)

#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    GPIO_PinInit(GPIO, BOARD_GPIO_PORT1, gpioPIN, &config);
    resp = (uint8_t)GPIO_PinRead(GPIO, BOARD_GPIO_PORT1, gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
    GPIO_PinInit(GPIO0, gpioPIN, &config);
    resp    = (uint8_t)GPIO_PinRead(GPIO0, gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
    GPIO_PinInit(GPIO2, gpioPIN, &config);
    resp    = (uint8_t)GPIO_PinRead(GPIO2, gpioPIN);
#endif
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));

#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    //Read PTB2

    status = nx_host_GPIOInit(NULL, gpioPIN, setInOutDir);
    ENSURE_OR_GO_CLEANUP(status == TRUE);

    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif

    if (resp == NX_HOSTGPIO_Read_Low) {
        LOG_I("Read HOST GPIO (PTB2): Low");
    }
    else {
        LOG_I("Read HOST GPIO (PTB2): High");
    }
    LOG_U8_D(resp);

    // Set gpio1 output set
    LOG_I("Set GPIO1.");
    gpioOperation = Nx_GPIOOutput_Set;
    sm_status =
        nx_ManageGPIO_Output(&((sss_nx_session_t *)pSession)->s_ctx, gpioNo, gpioOperation, NULL, 0, Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

#if SSS_HAVE_HOST_RASPBIAN
    gpioPIN = NX_HOST_RPI_INPUT_PIN_GPIO1;
    status  = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    resp = (uint8_t)GPIO_PinRead(GPIO, BOARD_GPIO_PORT1, gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
    resp    = (uint8_t)GPIO_PinRead(GPIO0, gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
    resp    = (uint8_t)GPIO_PinRead(GPIO2, gpioPIN);
#endif
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif

    if (resp == NX_HOSTGPIO_Read_High) {
        LOG_I("Read HOST GPIO (PTB2): High");
    }
    else {
        LOG_I("Read HOST GPIO (PTB2): Low");
    }
    LOG_U8_D(resp);

    // Set gpio1 output toggle
    LOG_I("Toggle GPIO1.");
    gpioOperation = Nx_GPIOOutput_Toggle;
    sm_status =
        nx_ManageGPIO_Output(&((sss_nx_session_t *)pSession)->s_ctx, gpioNo, gpioOperation, NULL, 0, Nx_CommMode_NA);

    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

#if SSS_HAVE_HOST_RASPBIAN
    gpioPIN = NX_HOST_RPI_INPUT_PIN_GPIO1;
    status  = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    resp = (uint8_t)GPIO_PinRead(GPIO, BOARD_GPIO_PORT1, gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
    resp    = (uint8_t)GPIO_PinRead(GPIO0, gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
    resp    = (uint8_t)GPIO_PinRead(GPIO2, gpioPIN);
#endif
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif
    if (resp == NX_HOSTGPIO_Read_High) {
        LOG_I("Read HOST GPIO (PTB2): High");
    }
    else {
        LOG_I("Read HOST GPIO (PTB2): Low");
    }
    LOG_U8_D(resp);

    gpioNo = Nx_GPIONo_2;

#if SSS_HAVE_HOST_RASPBIAN
    LOG_I("Set HOST GPIO (2) : Low");
    gpioPIN     = NX_HOST_RPI_INPUT_PIN_GPIO2;
    setInOutDir = NX_HOSTGPIOOutput; //Set OutPut direction

    status = nx_host_GPIOInit(NULL, gpioPIN, setInOutDir);
    ENSURE_OR_GO_CLEANUP(status == TRUE);

    status = nx_host_GPIOClear(NULL, gpioPIN);
    ENSURE_OR_GO_CLEANUP(status == TRUE);

#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)

#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    gpioPIN             = NX_HOSTGPIO_PIO1_8; //PIN8
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
    gpioPIN = BOARD_PIO0_26_GPIO_PIN; //PIN26
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
    gpioPIN = BOARD_P2_16_GPIO_PIN; //PIN16
#endif
    config.pinDirection = kGPIO_DigitalOutput;
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    GPIO_PinInit(GPIO, BOARD_GPIO_PORT1, gpioPIN, &config);
    GPIO_PortClear(GPIO, BOARD_GPIO_PORT1, 1U << gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
    GPIO_PinInit(GPIO0, gpioPIN, &config);
    GPIO_PortClear(GPIO0, 1U << gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
    GPIO_PinInit(GPIO2, gpioPIN, &config);
    GPIO_PortClear(GPIO2, 1U << gpioPIN);
#endif

#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    LOG_I("Set HOST GPIO (PTB3): Low");
    gpioPIN     = NX_HOSTGPIO_I02;
    setInOutDir = NX_HOSTGPIOOutput; //Set OutPut direction

    status = nx_host_GPIOInit(NULL, gpioPIN, setInOutDir);
    ENSURE_OR_GO_CLEANUP(status == TRUE);

    status = nx_host_GPIOClear(NULL, gpioPIN);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif

    // Read gpio2
    sm_status = nx_ReadGPIO(&((sss_nx_session_t *)pSession)->s_ctx,
        &tagTamperPermStatus,
        &gpio1CurrentOrTTCurrentStatus,
        &gpio2CurrentStatus,
        Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    inputStatus = gpio2CurrentStatus;
    if (inputStatus == Nx_GPIO_STATUS_LOW) {
        LOG_I("Read GPIO2 is low.");
    }
    else {
        LOG_I("Read GPIO2 is high.");
    }

#if SSS_HAVE_HOST_RASPBIAN
    LOG_I("Set HOST GPIO (2): High");
    status = nx_host_GPIOSet(NULL, gpioPIN);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)

#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
    GPIO_PortSet(GPIO, BOARD_GPIO_PORT1, 1U << gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
    GPIO_PortSet(GPIO0, 1U << gpioPIN);
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
    GPIO_PortSet(GPIO2, 1U << gpioPIN);
#endif
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    //SET PTB3 High
    LOG_I("Set HOST GPIO (PTB3): High");
    status = nx_host_GPIOSet(NULL, gpioPIN);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif // SSS_HAVE_SMCOM_VCOM

    // Read gpio2
    sm_status = nx_ReadGPIO(&((sss_nx_session_t *)pSession)->s_ctx,
        &tagTamperPermStatus,
        &gpio1CurrentOrTTCurrentStatus,
        &gpio2CurrentStatus,
        Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    inputStatus = gpio2CurrentStatus;
    if (inputStatus == Nx_GPIO_STATUS_HIGH) {
        LOG_I("Read GPIO2 is high.");
    }
    else {
        LOG_I("Read GPIO2 is low.");
    }

cleanup:

#if SSS_HAVE_HOST_RASPBIAN
    nx_host_GPIOClose(NULL, NX_HOST_RPI_INPUT_PIN_GPIO1);
    nx_host_GPIOClose(NULL, NX_HOST_RPI_INPUT_PIN_GPIO2);
#endif

    if (SM_OK == sm_status) {
        status = kStatus_SSS_Success;
        LOG_I("ex_sss_gpio Example Success !!!...");
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("ex_sss_gpio Example Failed !!!...");
    }
    return status;
}
