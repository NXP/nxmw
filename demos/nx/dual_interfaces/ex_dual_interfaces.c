/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include <string.h>
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM) || \
    defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) || defined(SSS_HAVE_HOST_RASPBIAN)
#include "nx_host_gpio.h"
#endif
#include "nx_apdu.h"
#include "nx_enums.h"
#include "sm_timer.h"
#if defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED)
#include "board.h"
#if defined(SSS_HAVE_CMSIS_DRIVER_ENABLED) && SSS_HAVE_CMSIS_DRIVER_ENABLED
#include "app.h"
#endif
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

static ex_sss_boot_ctx_t gex_dual_interfaces_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_dual_interfaces_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0
#define EX_SSS_BOOT_SKIP_SELECT_FILE 1

#define EX_DUAL_INTERFACE_NFC_PAUSE_FILE_NO NX_FILE_NDEF_FILE_NO

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    sss_nx_session_t *pSession = NULL;
    Nx_GPIONumber_t gpioNo     = Nx_GPIONo_2;
    uint8_t operation          = NX_MGMT_NFC_ACTION_RELEASE_NFC_PAUSE | Nx_GPIOOutput_Toggle;

    uint8_t fileNo              = EX_DUAL_INTERFACE_NFC_PAUSE_FILE_NO;
    size_t offset               = 0;
    uint8_t writeFileData[8]    = {0x01, 0x02, 0x03, 0x04, 0x5, 0x06, 0x07, 0x08};
    size_t writeFileDataLen     = sizeof(writeFileData);
    Nx_CommMode_t knownCommMode = Nx_CommMode_NA;

    uint8_t nfcPauseRespData[8] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
    size_t nfcPauseRespDataLen  = sizeof(nfcPauseRespData);

    U8 resp                = 0;
    uint8_t setInOutDir    = NX_HOSTGPIOInput; //Set Input direction
    uint8_t initGPIOStatus = 0xFF;

#if SSS_HAVE_HOST_RASPBIAN
    U16 respLen = 0;
    int gpioRet = -1;
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
    U8 gpioPIN = BOARD_GPIO_PIN_IO2; //PIN8
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    U8 gpioPIN  = NX_HOSTGPIO_I02; //PIN3
    U16 respLen = 0;
#endif

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    // Init MCU GPIO and read initial status.
#if SSS_HAVE_HOST_RASPBIAN
    respLen    = 0;
    U8 gpioPIN = NX_HOST_RPI_INPUT_PIN_GPIO2;

    status = nx_host_GPIOInit(NULL, gpioPIN, setInOutDir);
    ENSURE_OR_GO_CLEANUP(status == TRUE);

    resp   = 0xFF;
    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_CMSIS_DRIVER_ENABLED) && (SSS_HAVE_CMSIS_DRIVER_ENABLED)
    EXAMPLE_GPIO_INTERFACE.Setup(gpioPIN, NULL);
    EXAMPLE_GPIO_INTERFACE.SetDirection(gpioPIN, setInOutDir);
    resp = EXAMPLE_GPIO_INTERFACE.GetInput(gpioPIN);
#else
    gpio_pin_config_t config = {setInOutDir, 0};
    INIT_GPIO_PIN(gpioPIN, &config);
    resp = READ_GPIO_PIN(gpioPIN);
#endif
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    respLen = 0;
    status  = nx_host_GPIOInit(NULL, gpioPIN, setInOutDir);
    ENSURE_OR_GO_CLEANUP(status == TRUE);

    resp   = 0xFF;
    status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));

    initGPIOStatus = resp;
    if (initGPIOStatus == NX_HOSTGPIO_Read_Low) {
        LOG_I("HOST GPIO (PTB3) Init Status: Low");
    }
    else {
        LOG_I("HOST GPIO (PTB3) Init Status: High");
    }

    // Polling GPIO status until it changes.
    while (resp == initGPIOStatus) {
        resp = 0xFF;

#if SSS_HAVE_HOST_RASPBIAN
        respLen = 0;
        status  = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
        ENSURE_OR_GO_CLEANUP(status == TRUE);
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_CMSIS_DRIVER_ENABLED) && (SSS_HAVE_CMSIS_DRIVER_ENABLED)
        resp = EXAMPLE_GPIO_INTERFACE.GetInput(gpioPIN);
#else
        resp = READ_GPIO_PIN(gpioPIN);
#endif
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
        respLen = 0;

        status = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
        ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif
        ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));

        sm_sleep(1000);
    }

    if (resp == NX_HOSTGPIO_Read_Low) {
        LOG_I("HOST GPIO (PTB3) Status Changed: Low");
    }
    else {
        LOG_I("HOST GPIO (PTB3) Status Changed: High");
    }

    // Write File Data
    LOG_I("Write NDEF File Data (Offset 0x%x, Length 0x%x).", offset, writeFileDataLen);
    sm_status = nx_WriteData(
        &((sss_nx_session_t *)pSession)->s_ctx, fileNo, offset, writeFileData, writeFileDataLen, knownCommMode);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

    LOG_I("Read External I2C Sensor Could Be Called Here!");

    // Set gpio2 output toggle
    LOG_I("Toggle GPIO2 And Release NFC Pause.");
    sm_status = nx_ManageGPIO_Output(&((sss_nx_session_t *)pSession)->s_ctx,
        gpioNo,
        operation,
        nfcPauseRespData,
        nfcPauseRespDataLen,
        Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

    sm_status = SM_NOT_OK;

    // Read Host GPIO Status
    resp = 0xFF;

#if SSS_HAVE_HOST_RASPBIAN
    respLen = 0;
    status  = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_CMSIS_DRIVER_ENABLED) && (SSS_HAVE_CMSIS_DRIVER_ENABLED)
    resp = EXAMPLE_GPIO_INTERFACE.GetInput(gpioPIN);
#else
    resp = READ_GPIO_PIN(gpioPIN);
#endif
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    respLen = 0;
    status  = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
    ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif
    ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));

    if (resp == NX_HOSTGPIO_Read_Low) {
        LOG_I("Read HOST GPIO (PTB3): Low");
    }
    else {
        LOG_I("Read HOST GPIO (PTB3): High");
    }

    LOG_I("Wait session close until NFC pause");
    initGPIOStatus = resp;
    // Polling GPIO status until it changes.
    while (resp == initGPIOStatus) {
        resp = 0xFF;

#if SSS_HAVE_HOST_RASPBIAN
        respLen = 0;
        status  = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
        ENSURE_OR_GO_CLEANUP(status == TRUE);
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0) // Other MCU (K64F)
#if defined(SSS_HAVE_CMSIS_DRIVER_ENABLED) && (SSS_HAVE_CMSIS_DRIVER_ENABLED)
        resp = EXAMPLE_GPIO_INTERFACE.GetInput(gpioPIN);
#else
        resp = READ_GPIO_PIN(gpioPIN);
#endif
#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
        respLen = 0;
        status  = nx_host_GPIORead(NULL, gpioPIN, &resp, &respLen);
        ENSURE_OR_GO_CLEANUP(status == TRUE);
#endif
        ENSURE_OR_GO_CLEANUP((resp == NX_HOSTGPIO_Read_Low) || (resp == NX_HOSTGPIO_Read_High));

        sm_sleep(1000);
    }

    if (resp == NX_HOSTGPIO_Read_Low) {
        LOG_I("HOST GPIO (PTB3) Status Changed: Low");
    }
    else {
        LOG_I("HOST GPIO (PTB3) Status Changed: High");
    }
    sm_status = SM_OK;

cleanup:

#if SSS_HAVE_HOST_RASPBIAN
    nx_host_GPIOClose(NULL, NX_HOST_RPI_INPUT_PIN_GPIO2);
#endif

    if (SM_OK == sm_status) {
        status = kStatus_SSS_Success;
        LOG_I("ex_dual_interfaces Example Success !!!...");
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("ex_dual_interfaces Example Failed !!!...");
    }
    return status;
}
