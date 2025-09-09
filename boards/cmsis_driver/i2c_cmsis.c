/*
 * Copyright 2025 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <board.h>
#include <stdio.h>
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && FSL_FEATURE_SOC_LPI2C_COUNT > 0
#include "i2c_a7.h"
#include "fsl_clock.h"
#include "fsl_lpi2c.h"
#include "sm_timer.h"
#include "fsl_debug_console.h"
#include "fsl_lpi2c_cmsis.h"
#include "fsl_port.h"
#include "app.h"

#define I2C_LOG_PRINTF PRINTF

volatile bool g_MasterCompletionFlag = false;
i2c_error_t g_MasterretStatus;

#if defined(FLOW_SILENT)
#define DEBUG_PRINT_KINETIS_I2C(Operation, status)
#elif 1 || defined(I2C_DEBUG) || 1
#define DEBUG_PRINT_KINETIS_I2C(Operation, status)                                                   \
    if (g_MasterretStatus == I2C_OK) { /* I2C_LOG_PRINTF(Operation " OK\r\n");*/                     \
    }                                                                                                \
    else if (g_MasterretStatus == I2C_BUSY) { /*I2C_LOG_PRINTF(Operation " Busy\r\n");*/             \
    }                                                                                                \
    else if (g_MasterretStatus == I2C_NACK_ON_ADDRESS) { /* I2C_LOG_PRINTF(Operation " Nak\r\n"); */ \
    }                                                                                                \
    else if (g_MasterretStatus == I2C_ARBITRATION_LOST)                                              \
        I2C_LOG_PRINTF(Operation " ArbtnLost\r\n");                                                  \
    else                                                                                             \
        I2C_LOG_PRINTF(Operation " ERROR  : 0x%02lX\r\n", status);
#else
#define DEBUG_PRINT_KINETIS_I2C(Operation, status)
#endif

/* Handle NAK from the NX */
static int gBackoffDelay;

void axI2CResetBackoffDelay()
{
    gBackoffDelay = 0;
}

static void BackOffDelay_Wait()
{
    if (gBackoffDelay < 200) {
        gBackoffDelay += 1;
    }
    sm_sleep(gBackoffDelay);
}

static void lpi2c_master_callback(uint32_t event)
{
    switch (event) {
    /* The master has sent a stop transition on the bus */
    case ARM_I2C_EVENT_TRANSFER_DONE:
        g_MasterretStatus      = I2C_OK;
        g_MasterCompletionFlag = true;
        break;

    case ARM_I2C_EVENT_TRANSFER_INCOMPLETE:
        g_MasterretStatus      = I2C_BUSY;
        g_MasterCompletionFlag = true;
        break;

    case ARM_I2C_EVENT_SLAVE_TRANSMIT:
        g_MasterretStatus      = I2C_FAILED;
        g_MasterCompletionFlag = true;
        break;

    case ARM_I2C_EVENT_SLAVE_RECEIVE:
        g_MasterretStatus      = I2C_FAILED;
        g_MasterCompletionFlag = true;
        break;

    case ARM_I2C_EVENT_ADDRESS_NACK:
        g_MasterretStatus      = I2C_NACK_ON_ADDRESS;
        g_MasterCompletionFlag = true;
        break;

    case ARM_I2C_EVENT_GENERAL_CALL:
        g_MasterretStatus      = I2C_FAILED;
        g_MasterCompletionFlag = true;
        break;

    case ARM_I2C_EVENT_ARBITRATION_LOST:
        g_MasterretStatus      = I2C_ARBITRATION_LOST;
        g_MasterCompletionFlag = true;
        break;

    case ARM_I2C_EVENT_BUS_ERROR:
        g_MasterretStatus      = I2C_FAILED;
        g_MasterCompletionFlag = true;
        break;

    case ARM_I2C_EVENT_BUS_CLEAR:
        g_MasterCompletionFlag = true;
        break;

    default:
        g_MasterretStatus      = I2C_FAILED;
        g_MasterCompletionFlag = true;
        break;
    }
}

void handleI2C_Status(uint32_t handleI2CStatus)
{
    if (handleI2CStatus == I2C_NACK_ON_DATA || handleI2CStatus == I2C_NACK_ON_ADDRESS) {
        BackOffDelay_Wait();
    }
    else if (handleI2CStatus == I2C_OK) {
        axI2CResetBackoffDelay();
    }
}

i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    /* Initialize the LPI2C master peripheral */
    I2C_DEVICE_TYPE *pDevHandle = (conn_ctx != NULL) ? (I2C_DEVICE_TYPE *)conn_ctx : I2C_DEVICE_HANDLE;
    if (pDevHandle == AX_I2C3M) {
        I2C_MASTER_I2C3.Initialize(lpi2c_master_callback);
        I2C_MASTER_I2C3.PowerControl(ARM_POWER_FULL);

        /* Change the default baudrate configuration */
        I2C_MASTER_I2C3.Control(ARM_I2C_BUS_SPEED, ARM_I2C_BUS_SPEED_STANDARD);
    }
    else {
        I2C_MASTER_BASE.Initialize(lpi2c_master_callback);
        I2C_MASTER_BASE.PowerControl(ARM_POWER_FULL);

        /* Change the default baudrate configuration */
        I2C_MASTER_BASE.Control(ARM_I2C_BUS_SPEED, ARM_I2C_BUS_SPEED_STANDARD);
    }
    return I2C_OK;
}

void axI2CTerm(void *conn_ctx, int mode)
{
}

unsigned int axI2CWrite(
    void *conn_ctx, unsigned char bus_unused_param, unsigned char addr, unsigned char *pTx, unsigned short txLen)
{
    g_MasterretStatus           = I2C_FAILED;
    I2C_DEVICE_TYPE *pDevHandle = (conn_ctx != NULL) ? (I2C_DEVICE_TYPE *)conn_ctx : I2C_DEVICE_HANDLE;
    if (pDevHandle == AX_I2C3M) {
        I2C_MASTER_I2C3.MasterTransmit((addr >> 1), pTx, txLen, false);
    }
    else {
        I2C_MASTER_BASE.MasterTransmit((addr >> 1), pTx, txLen, false);
    }
    /*wait for master complete*/
    while (!g_MasterCompletionFlag) {
    }
    handleI2C_Status(g_MasterretStatus);

    /*  Reset master completion flag to false. */
    g_MasterCompletionFlag = false;
    DEBUG_PRINT_KINETIS_I2C("WR", g_MasterretStatus);

    return g_MasterretStatus;
}

unsigned int axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pRx, unsigned short rxLen)
{
    g_MasterretStatus           = I2C_FAILED;
    I2C_DEVICE_TYPE *pDevHandle = (conn_ctx != NULL) ? (I2C_DEVICE_TYPE *)conn_ctx : I2C_DEVICE_HANDLE;
    if (pDevHandle == AX_I2C3M) {
        I2C_MASTER_I2C3.MasterReceive((addr >> 1), pRx, rxLen, false);
    }
    else {
        I2C_MASTER_BASE.MasterReceive((addr >> 1), pRx, rxLen, false);
    }
    /*wait for master complete*/
    while (!g_MasterCompletionFlag) {
    }
    handleI2C_Status(g_MasterretStatus);

    /*  Reset master completion flag to false. */
    g_MasterCompletionFlag = false;
    DEBUG_PRINT_KINETIS_I2C("RD", g_MasterretStatus);

    return g_MasterretStatus;
}

#endif /* FSL_FEATURE_SOC_I2C_COUNT */