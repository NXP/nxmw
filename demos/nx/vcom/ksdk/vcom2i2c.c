/* Copyright 2018, 2020, 2022-2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "vcom2i2c.h"
#include "virtual_com.h"

#include "board.h"
#include "se_pit_config.h"

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && FSL_FEATURE_SOC_LPI2C_COUNT > 0
#include "fsl_lpi2c.h" // A71CH I2C
#endif

#if defined(FSL_FEATURE_SOC_I2C_COUNT) && (FSL_FEATURE_SOC_I2C_COUNT > 0)
#include "fsl_i2c.h" // A71CH I2C
#endif

//+ A71CH I2C
#include <stdbool.h>
#include <sm_types.h>
#include "smComT1oI2C.h"
#include "sm_apdu.h"
#include "sm_timer.h"

#include "nxLog_msg.h"

#define ESTABLISH_SCI2C 0x00
#define RESUME_SCI2C 0x01

static uint8_t s_FrameParseInProgress = 0;
static uint16_t curr_index            = 0;
static uint8_t g_sendresp_vcom        = 0;
static uint8_t g_senddata_i2c         = 0;

U32 selectResponseDataLen = 0;

#if defined(CPU_MCXA153VLH)
//USB_DMA_NONINIT_DATA_ALIGN
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static U8 selectResponseData[1024 + 20];

//USB_DMA_NONINIT_DATA_ALIGN
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t targetBuffer[1024 + 20] = {0};

static uint8_t s_RecvBuff[1024 + 10];
#else
//USB_DMA_NONINIT_DATA_ALIGN
USB_DMA_NONINIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static U8 selectResponseData[2048 + 20];

//USB_DMA_NONINIT_DATA_ALIGN
USB_DMA_INIT_DATA_ALIGN(USB_DATA_ALIGN_SIZE) static uint8_t targetBuffer[2048 + 20] = {0};

static uint8_t s_RecvBuff[2048 + 10];
#endif

uint16_t targetBufferLen         = 0;
static uint32_t nExpectedPayload = 0;

void state_vcom_read_write(
    usb_cdc_vcom_struct_t *p_cdcVcom, volatile uint32_t *p_recvSize, const uint8_t s_currRecvBuf[DATA_BUFF_SIZE])
{
    sm_sleep(1);
    usb_status_t error   = kStatus_USB_Error;
    uint16_t statusValue = 0;
    U16 sw               = SW_OK;
    if ((1 == p_cdcVcom->attach) && (1 == p_cdcVcom->startTransactions)) {
        LOG_W("L1");
        /* User Code */
        if ((0 != (*p_recvSize)) && (0xFFFFFFFFU != (*p_recvSize))) {
            LOG_W("VCOM Rd");
            if (s_FrameParseInProgress == 0) {
                nExpectedPayload = (s_currRecvBuf[2] << 8) + s_currRecvBuf[3];
            }

            if (nExpectedPayload > ((*p_recvSize) + curr_index - 4)) {
                s_FrameParseInProgress = 1;
                memcpy(&s_RecvBuff[curr_index], s_currRecvBuf, (*p_recvSize));
                curr_index += (*p_recvSize);
            }
            else {
                s_FrameParseInProgress = 0;
                memcpy(&s_RecvBuff[curr_index], s_currRecvBuf, (*p_recvSize));
                curr_index += (*p_recvSize);
            }

            if ((curr_index == (nExpectedPayload + 4)) && (s_FrameParseInProgress == 0)) {
                curr_index = 0;
                switch (s_RecvBuff[0]) {
#if defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED)
                case GPIO_PIN_INIT: {
                    LOG_I("GPIO_PIN_INIT ........ ");
                    uint8_t setInOutDir      = 0;
                    uint8_t gpioPIN          = s_RecvBuff[4];
                    setInOutDir              = s_RecvBuff[5];
                    gpio_pin_config_t config = {
                        setInOutDir,
                        0,
                    };
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PinInit(GPIO, BOARD_GPIO_PORT1, BOARD_PIO1_8_GPIO_PIN, &config);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PinInit(GPIO, BOARD_GPIO_PORT1, BOARD_PIO1_5_GPIO_PIN, &config);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PinInit(GPIO0, BOARD_PIO0_26_GPIO_PIN, &config);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PinInit(GPIO0, BOARD_PIO0_25_GPIO_PIN, &config);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PinInit(GPIO2, BOARD_P2_16_GPIO_PIN, &config);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PinInit(GPIO2, BOARD_P2_12_GPIO_PIN, &config);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#endif
                    targetBufferLen = sizeof(targetBuffer);
                    statusValue =
                        vcomPackageApduResponse(GPIO_PIN_INIT, 0x00, NULL, 0x00, targetBuffer, &targetBufferLen);
                    if (statusValue == RJCT_OK) {
                        memcpy(selectResponseData, targetBuffer, targetBufferLen);
                        selectResponseDataLen = targetBufferLen;
                        g_sendresp_vcom       = 1;
                    }
                    else {
                        LOG_X16_E(statusValue);
                    }
                } break;
                case GPIO_PORT_SET: {
                    LOG_I("GPIO_PORT_SET  ........ ");
                    uint8_t gpioPIN = s_RecvBuff[4];
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortSet(GPIO, BOARD_GPIO_PORT1, 1U << BOARD_PIO1_8_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortSet(GPIO, BOARD_GPIO_PORT1, 1U << BOARD_PIO1_5_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortSet(GPIO0, 1U << BOARD_PIO0_26_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortSet(GPIO0, 1U << BOARD_PIO0_25_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortSet(GPIO2, 1U << BOARD_P2_16_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortSet(GPIO2, 1U << BOARD_P2_12_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#endif
                    targetBufferLen = sizeof(targetBuffer);
                    statusValue =
                        vcomPackageApduResponse(GPIO_PORT_SET, 0x00, NULL, 0x00, targetBuffer, &targetBufferLen);
                    if (statusValue == RJCT_OK) {
                        memcpy(selectResponseData, targetBuffer, targetBufferLen);
                        selectResponseDataLen = targetBufferLen;
                        g_sendresp_vcom       = 1;
                    }
                    else {
                        LOG_X16_E(statusValue);
                    }
                } break;
                case GPIO_PORT_CLEAR: {
                    LOG_I("GPIO_PORT_CLEAR  ........ ");
                    uint8_t gpioPIN = s_RecvBuff[4];
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortClear(GPIO, BOARD_GPIO_PORT1, 1U << BOARD_PIO1_8_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortClear(GPIO, BOARD_GPIO_PORT1, 1U << BOARD_PIO1_5_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortClear(GPIO0, 1U << BOARD_PIO0_26_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortClear(GPIO0, 1U << BOARD_PIO0_25_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortClear(GPIO2, 1U << BOARD_P2_16_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortClear(GPIO2, 1U << BOARD_P2_12_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#endif
                    targetBufferLen = sizeof(targetBuffer);
                    statusValue =
                        vcomPackageApduResponse(GPIO_PORT_CLEAR, 0x00, NULL, 0x00, targetBuffer, &targetBufferLen);
                    if (statusValue == RJCT_OK) {
                        memcpy(selectResponseData, targetBuffer, targetBufferLen);
                        selectResponseDataLen = targetBufferLen;
                        g_sendresp_vcom       = 1;
                    }
                    else {
                        LOG_X16_E(statusValue);
                    }

                } break;
                case GPIO_PORT_TOGGLE: {
                    LOG_I("GPIO_PORT_TOGGLE  ........ ");
                    uint8_t gpioPIN = s_RecvBuff[4];
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortToggle(GPIO, BOARD_GPIO_PORT1, 1U << BOARD_PIO1_8_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortToggle(GPIO, BOARD_GPIO_PORT1, 1U << BOARD_PIO1_5_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortToggle(GPIO0, 1U << BOARD_PIO0_26_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortToggle(GPIO0, 1U << BOARD_PIO0_25_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        GPIO_PortToggle(GPIO2, 1U << BOARD_P2_16_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        GPIO_PortToggle(GPIO2, 1U << BOARD_P2_12_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#endif
                    targetBufferLen = sizeof(targetBuffer);
                    statusValue =
                        vcomPackageApduResponse(GPIO_PORT_TOGGLE, 0x00, NULL, 0x00, targetBuffer, &targetBufferLen);
                    if (statusValue == RJCT_OK) {
                        memcpy(selectResponseData, targetBuffer, targetBufferLen);
                        selectResponseDataLen = targetBufferLen;
                        g_sendresp_vcom       = 1;
                    }
                    else {
                        LOG_X16_E(statusValue);
                    }
                } break;
                case GPIO_PIN_READ: {
                    LOG_I("GPIO_PIN_READ  ........ ");
                    uint8_t gpioPIN = s_RecvBuff[4];
                    uint8_t a       = 0xFF;
#if defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        a = (uint8_t)GPIO_PinRead(GPIO, BOARD_GPIO_PORT1, BOARD_PIO1_8_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        a = (uint8_t)GPIO_PinRead(GPIO, BOARD_GPIO_PORT1, BOARD_PIO1_5_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        a = (uint8_t)GPIO_PinRead(GPIO0, BOARD_PIO0_26_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        a = (uint8_t)GPIO_PinRead(GPIO0, BOARD_PIO0_25_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
                    if (gpioPIN == MCU_GPIO_PIN_IO2) {
                        a = (uint8_t)GPIO_PinRead(GPIO2, BOARD_P2_16_GPIO_PIN);
                    }
                    else if (gpioPIN == MCU_GPIO_PIN_IO1) {
                        a = (uint8_t)GPIO_PinRead(GPIO2, BOARD_P2_12_GPIO_PIN);
                    }
                    else {
                        LOG_I("Invalid gpioPIN");
                    }

#endif
                    targetBufferLen = sizeof(targetBuffer);
                    statusValue =
                        vcomPackageApduResponse(GPIO_PIN_READ, 0x00, &a, sizeof(a), targetBuffer, &targetBufferLen);
                    if (statusValue == RJCT_OK) {
                        memcpy(selectResponseData, targetBuffer, targetBufferLen);
                        selectResponseDataLen = targetBufferLen;
                        g_sendresp_vcom       = 1;
                    }
                    else {
                        LOG_X16_E(statusValue);
                    }
                } break;
#endif
                case WAIT_FOR_CARD: {
                    LOG_I("Waiting for card ........ ");
                    U8 Cip[64];
                    U16 CipLen = sizeof(Cip);

                    CipLen = sizeof(Cip);
#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
                    sw = smComT1oI2C_Open(NULL, ESTABLISH_SCI2C, 0x00, Cip, &CipLen);
#endif
                    if (sw == SW_OK) {
                        targetBufferLen = sizeof(targetBuffer);
                        statusValue = vcomPackageApduResponse(0x00, 0x00, Cip, CipLen, targetBuffer, &targetBufferLen);
                        if (statusValue == RJCT_OK) {
                            memcpy(selectResponseData, targetBuffer, targetBufferLen);
                            selectResponseDataLen = targetBufferLen;
                            g_sendresp_vcom       = 1;
                        }
                        else {
                            LOG_X16_E(statusValue);
                        }
                    }
                    else {
                        Cip[0]          = 0x69;
                        Cip[1]          = 0x82;
                        CipLen          = 2;
                        targetBufferLen = sizeof(targetBuffer);
                        statusValue = vcomPackageApduResponse(0x00, 0x00, Cip, CipLen, targetBuffer, &targetBufferLen);
                        if (targetBufferLen > sizeof(selectResponseData)) {
                            LOG_E("targetBufferLen=%d > sizeof(selectResponseData)=%d",
                                targetBufferLen,
                                sizeof(selectResponseData));
                        }
                        if ((statusValue == RJCT_OK) && (targetBufferLen <= sizeof(selectResponseData))) {
                            memcpy(selectResponseData, targetBuffer, targetBufferLen);
                            selectResponseDataLen = targetBufferLen;
                            g_sendresp_vcom       = 1;
                        }
                        else {
                            LOG_X16_E(statusValue);
                        }

                        LOG_E("Communication failed ");
                    }
                } break;
                case APDU_DATA:
                    if (s_RecvBuff[4] == 0xFF) {
                        uint32_t time_ms;
                        time_ms = (s_RecvBuff[6] << 24);
                        time_ms |= (s_RecvBuff[7] << 16);
                        time_ms |= (s_RecvBuff[8] << 8);
                        time_ms |= s_RecvBuff[9];
#if SSS_HAVE_NX_TYPE || SSS_HAVE_NX_TYPE_LOOPBACK
#if FSL_FEATURE_SOC_PIT_COUNT > 0
                        LOG_W("Starting the %d usec Timer to reset the IC", time_ms);
                        se_pit_SetTimer(time_ms);
                        g_sendresp_vcom = 1;
#endif
#endif
                    }
                    else {
                        LOG_D("Sending data");
                        g_senddata_i2c = 1;
                    }
                    break;
                case CLOSE_CONN:
                    LOG_I("Closing connection");

#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
                    sw = smComT1oI2C_Close(NULL, 0);
#endif
                    if (sw == SW_OK) {
                        targetBufferLen = sizeof(targetBuffer);
                        statusValue     = vcomPackageApduResponse(
                            CLOSE_CONN, 0x00, (U8 *)&sw, sizeof(sw), targetBuffer, &targetBufferLen);
                        if (statusValue == RJCT_OK) {
                            memcpy(selectResponseData, targetBuffer, targetBufferLen);
                            selectResponseDataLen = targetBufferLen;
                            g_sendresp_vcom       = 1;
                        }
                        else {
                            LOG_X16_E(statusValue);
                        }
                    }
                    else {
                        U8 resp[2];
                        U16 respLen = sizeof(resp);
                        resp[0]     = 0x69;
                        resp[1]     = 0x82;
                        LOG_E("Failed to Close connection");
                        targetBufferLen = sizeof(targetBuffer);
                        statusValue =
                            vcomPackageApduResponse(CLOSE_CONN, 0x00, resp, respLen, targetBuffer, &targetBufferLen);
                        if (statusValue == RJCT_OK) {
                            memcpy(selectResponseData, targetBuffer, targetBufferLen);
                            selectResponseDataLen = targetBufferLen;
                            g_sendresp_vcom       = 1;
                        }
                        else {
                            LOG_X16_E(statusValue);
                        }
                    }
                    break;
                default:
#if DEBUG
                    LOG_E("Error");
#endif
                    break;
                }
            }
            *p_recvSize = 0;
        }

        if (g_sendresp_vcom) {
            g_sendresp_vcom = 0;
            error           = USB_DeviceCdcAcmSend(
                p_cdcVcom->cdcAcmHandle, USB_CDC_VCOM_BULK_IN_ENDPOINT, selectResponseData, selectResponseDataLen);

            if (error != kStatus_USB_Success) {
                /* Failure to send Data Handling code here */
                LOG_E("Fail to send Data");
            }
        }
        else if (s_FrameParseInProgress == 1) {
            error = USB_DeviceCdcAcmSend(p_cdcVcom->cdcAcmHandle, USB_CDC_VCOM_BULK_IN_ENDPOINT, NULL, 0);

            if (error != kStatus_USB_Success) {
                /* Failure to send Data Handling code here */
                LOG_E("USB_DeviceCdcAcmSend: Fail to send Data");
            }
        }
        state_vcom_usbLowPower();
    }
}

void state_vcom_2_i2c()
{
    U16 sw;
    if (g_senddata_i2c) {
        U16 u16RespLen;
        g_senddata_i2c = 0;
        memset(selectResponseData, 0, sizeof(selectResponseData));
        selectResponseDataLen = sizeof(selectResponseData) - 4;
        u16RespLen            = (U16)selectResponseDataLen;
        if (nExpectedPayload > UINT16_MAX) {
            LOG_E("nExpectedPayload can not be greater than 2 bytes.");
            return;
        }
        sw                    = SM_SendAPDUVcom(&s_RecvBuff[4], nExpectedPayload, selectResponseData, &u16RespLen);
        selectResponseDataLen = u16RespLen;
        if (sw == SW_OK) {
            targetBufferLen = sizeof(targetBuffer);
            sw              = vcomPackageApduResponse(
                APDU_DATA, 0x00, selectResponseData, selectResponseDataLen, targetBuffer, &targetBufferLen);
            if (targetBufferLen > sizeof(selectResponseData)) {
                LOG_E(
                    "targetBufferLen=%d > sizeof(selectResponseData)=%d", targetBufferLen, sizeof(selectResponseData));
            }
            if ((sw == RJCT_OK) && (targetBufferLen <= sizeof(selectResponseData))) {
                memcpy(selectResponseData, targetBuffer, targetBufferLen);
                selectResponseDataLen = targetBufferLen;
                g_sendresp_vcom       = 1;
            }
            else {
                LOG_X16_E(sw);
            }
        }
        else {
            uint16_t statusValue = 0;
            U8 resp[2];
            U16 respLen = sizeof(resp);
            LOG_E("SM_SendAPDUVcom Failed");

            resp[0]         = ERR_COMM_ERROR >> 8;
            resp[1]         = ERR_COMM_ERROR & 0xFF;
            targetBufferLen = sizeof(targetBuffer);
            statusValue     = vcomPackageApduResponse(APDU_DATA, 0x00, resp, respLen, targetBuffer, &targetBufferLen);
            if (targetBufferLen > sizeof(selectResponseData)) {
                LOG_E(
                    "targetBufferLen=%d > sizeof(selectResponseData)=%d", targetBufferLen, sizeof(selectResponseData));
            }
            if ((statusValue == RJCT_OK) && (targetBufferLen <= sizeof(selectResponseData))) {
                memcpy(selectResponseData, targetBuffer, targetBufferLen);
                selectResponseDataLen = targetBufferLen;
                g_sendresp_vcom       = 1;
            }
            else {
                LOG_X16_E(statusValue);
            }
        }
    }
}

//+ A71CH I2C
U16 vcomPackageApduResponse(
    U8 messageType, U8 nodeAddress, U8 *payload, U16 payloadLen, U8 *targetBuf, U16 *targetBufLen)
{
    if ((NULL == targetBuf) || (NULL == targetBufLen)) {
        return RJCT_ARG_FAIL;
    }
    if (*targetBufLen < (4 + payloadLen)) {
        LOG_W("Target buffer provided too small.");
        return RJCT_ARG_FAIL;
    }

    targetBuf[0] = messageType;
    targetBuf[1] = nodeAddress;
    targetBuf[2] = (payloadLen >> 8) & 0x00FF;
    targetBuf[3] = payloadLen & 0x00FF;
    memcpy(&targetBuf[4], payload, payloadLen);
    if ((UINT16_MAX - 4) < payloadLen) {
        return RJCT_ARG_FAIL;
    }
    *targetBufLen = 4 + payloadLen;
    return RJCT_OK;
}

U16 SM_SendAPDUVcom(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen)
{
    U32 status       = 0;
    U32 respLenLocal = 0;
    if (NULL == respLen) {
        return (U16)status;
    }
    respLenLocal = *respLen;

    status = smCom_TransceiveRaw(NULL, cmd, cmdLen, resp, &respLenLocal);
    if (status != SMCOM_OK) {
        LOG_E("Failed to communicate with IC");
    }
    if (respLenLocal > UINT16_MAX) {
        LOG_E("respLenLocal can not be greater than 2 bytes.");
        return SMCOM_COM_FAILED;
    }
    *respLen = (U16)respLenLocal;

    return (U16)status;
}
//- A71CH I2C
