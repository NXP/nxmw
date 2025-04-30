/*
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * I2C implmentation for ICs related to MCXA Family
 */

#define MAX_DATA_LEN 260

#include <board.h>
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(FSL_FEATURE_SOC_LPI2C_COUNT) && FSL_FEATURE_SOC_LPI2C_COUNT > 0 && defined(MCXA)
#include "i2c_a7.h"
#include "fsl_clock.h"
#include "fsl_lpi2c.h"
#if defined(SDK_OS_FREE_RTOS) && SDK_OS_FREE_RTOS == 1
#include "fsl_lpi2c_freertos.h"
#endif
#include "fsl_port.h"
#include "fsl_i3c.h"
#include "sm_timer.h"
#include <stdio.h>
#include "fsl_gpio.h"
#include "nxLog_msg.h"

#define AX_I2CM ((LPI2C_Type *)(LPI2C0_BASE))
#define AX_I2C_CLK_SRC CLOCK_GetLpi2cClkFreq()
// #define AX_I2CM_IRQN   I2C2_IRQn

#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0)
#define I2C_BAUDRATE 100000U
#else
#error "Invalid combination"
#endif

#include "nxLog_msg.h"

//#define I2C_DEBUG
//#define DELAY_I2C_US          (T_CMDG_USec)
#define DELAY_I2C_US (0)

#define I3C_MASTER I3C0
#define I3C_BAUDRATE 100000
#define I3C_OD_BAUDRATE 375000
#define I3C_PP_BAUDRATE 750000
#define I3C_MASTER_CLOCK_FREQUENCY CLOCK_GetI3CFClkFreq()
#define I3C_WAIT_TIME 10000

#define I2C_LOG_PRINTF printf

#if defined(FLOW_SILENT)
#define DEBUG_PRINT_KINETIS_I2C(Operation, status)
#elif 1 || defined(I2C_DEBUG) || 1
#define DEBUG_PRINT_KINETIS_I2C(Operation, status)                                                \
    if (result == kStatus_Success) { /* I2C_LOG_PRINTF(Operation " OK\r\n");                   */ \
    }                                                                                             \
    else if (result == kStatus_LPI2C_Busy)                                                        \
        I2C_LOG_PRINTF(Operation " Busy\r\n");                                                    \
    else if (result == kStatus_LPI2C_Idle)                                                        \
        I2C_LOG_PRINTF(Operation " Idle\r\n");                                                    \
    else if (result == kStatus_LPI2C_Nak) { /* I2C_LOG_PRINTF(Operation " Nak\r\n"); */           \
    }                                                                                             \
    else if (result == kStatus_LPI2C_Timeout)                                                     \
        I2C_LOG_PRINTF(Operation " T/O\r\n");                                                     \
    else if (result == kStatus_LPI2C_ArbitrationLost)                                             \
        I2C_LOG_PRINTF(Operation " ArbtnLost\r\n");                                               \
    else                                                                                          \
        I2C_LOG_PRINTF(Operation " ERROR  : 0x%02lX\r\n", status);
#else
#define DEBUG_PRINT_KINETIS_I2C(Operation, status)
#endif

/* Handle NAK from NX */
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

static i2c_error_t kinetisI2cStatusToAxStatus(status_t kinetis_i2c_status)
{
    i2c_error_t retStatus;
    switch (kinetis_i2c_status) {
    case kStatus_Success:
        axI2CResetBackoffDelay();
        retStatus = I2C_OK;
        break;
    case kStatus_LPI2C_Busy:
        BackOffDelay_Wait();
        retStatus = I2C_BUSY;
        break;
    case kStatus_LPI2C_Idle:
        retStatus = I2C_BUSY;
        break;
    case kStatus_LPI2C_Nak:
        BackOffDelay_Wait();
        retStatus = I2C_NACK_ON_DATA;
        break;
    case kStatus_LPI2C_ArbitrationLost:
        retStatus = I2C_ARBITRATION_LOST;
        break;
    case kStatus_LPI2C_Timeout:
        retStatus = I2C_TIME_OUT;
        break;
    case kStatus_I3C_Busy:
        BackOffDelay_Wait();
        retStatus = I2C_BUSY;
        break;
    case kStatus_I3C_Idle:
        retStatus = I2C_BUSY;
        break;
    case kStatus_I3C_Nak:
        I3C_MasterStop(I3C_MASTER);
        BackOffDelay_Wait();
        retStatus = I2C_NACK_ON_DATA;
        break;
    case kStatus_I3C_Timeout:
        BackOffDelay_Wait();
        retStatus = I2C_TIME_OUT;
        break;
    case kStatus_I3C_InvalidStart:
        BackOffDelay_Wait();
        retStatus = I2C_NACK_ON_DATA;
        break;
    default:
        retStatus = I2C_FAILED;
        break;
    }
    return retStatus;
}

#define RETURN_ON_BAD_kinetisI2cStatus(kinetis_i2c_status)                      \
    {                                                                           \
        i2c_error_t ax_status = kinetisI2cStatusToAxStatus(kinetis_i2c_status); \
        if (ax_status != I2C_OK)                                                \
            return ax_status;                                                   \
    }

#if defined(SDK_OS_FREE_RTOS) && SDK_OS_FREE_RTOS == 1
lpi2c_rtos_handle_t gmaster_rtos_handle;
#endif

#if defined(SDK_OS_FREE_RTOS) && SDK_OS_FREE_RTOS == 1
#define I2CM_TX() result = LPI2C_RTOS_Transfer(&gmaster_rtos_handle, &masterXfer)
#else
#define I2CM_TX() result = LPI2C_MasterTransferBlocking(AX_I2CM, &masterXfer)
#endif

i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    lpi2c_master_config_t i2cMasterConfig;
    i3c_master_config_t i3cMasterConfig;

    I3C_MasterGetDefaultConfig(&i3cMasterConfig);
    i3cMasterConfig.baudRate_Hz.i2cBaud          = I3C_BAUDRATE;
    i3cMasterConfig.baudRate_Hz.i3cPushPullBaud  = I3C_PP_BAUDRATE;
    i3cMasterConfig.baudRate_Hz.i3cOpenDrainBaud = I3C_OD_BAUDRATE;
    i3cMasterConfig.enableOpenDrainStop          = false;
    I3C_MasterInit(I3C_MASTER, &i3cMasterConfig, I3C_MASTER_CLOCK_FREQUENCY);

    /*
    * Default I2C configuration:
    * i2cMasterConfig.baudRate_Bps = 100000U;
    * i2cMasterConfig.enableHighDrive = false;
    * i2cMasterConfig.enableStopHold = false;
    * i2cMasterConfig.glitchFilterWidth = 0U;
    * i2cMasterConfig.enableMaster = true;
    */

    LPI2C_MasterGetDefaultConfig(&i2cMasterConfig);
    i2cMasterConfig.baudRate_Hz = I2C_BAUDRATE;

#if defined(SDK_OS_FREE_RTOS) && SDK_OS_FREE_RTOS == 1
    LPI2C_RTOS_Init(&gmaster_rtos_handle, AX_I2CM, &i2cMasterConfig, AX_I2C_CLK_SRC);
#else
    LPI2C_MasterInit(AX_I2CM, &i2cMasterConfig, AX_I2C_CLK_SRC);
#endif

    return I2C_OK;
}

void axI2CTerm(void *conn_ctx, int mode)
{
#if defined(SDK_OS_FREE_RTOS) && SDK_OS_FREE_RTOS == 1
    LPI2C_RTOS_Deinit(&gmaster_rtos_handle);
#endif
}

unsigned int axI2CWrite(
    void *conn_ctx, unsigned char bus_unused_param, unsigned char addr, unsigned char *pTx, unsigned short txLen)
{
    status_t result;

    if (conn_ctx == I3C0) {
        // I3C channel used for communication

        i3c_master_transfer_t masterXfer;
        memset(&masterXfer, 0, sizeof(masterXfer)); //clear values

        masterXfer.slaveAddress   = addr >> 1; // the address of the NX
        masterXfer.direction      = kI3C_Write;
        masterXfer.busType        = kI3C_TypeI2C;
        masterXfer.subaddress     = 0x00;
        masterXfer.subaddressSize = 0;
        masterXfer.data           = pTx;
        masterXfer.dataSize       = txLen;
        masterXfer.flags          = kI3C_TransferDefaultFlag;

        result = I3C_MasterTransferBlocking(I3C_MASTER, &masterXfer);
    }
    else {
        // I2C channel used for communication

        lpi2c_master_transfer_t masterXfer;
        memset(&masterXfer, 0, sizeof(masterXfer)); //clear values

        if (pTx == NULL || txLen > MAX_DATA_LEN) {
            return I2C_FAILED;
        }

        masterXfer.slaveAddress   = addr >> 1; // the address of the NX
        masterXfer.direction      = kLPI2C_Write;
        masterXfer.subaddress     = 0;
        masterXfer.subaddressSize = 0;
        masterXfer.data           = pTx;
        masterXfer.dataSize       = txLen;
        masterXfer.flags          = kLPI2C_TransferDefaultFlag;

        I2CM_TX();
        // DEBUG_PRINT_KINETIS_I2C("WR", result);
    }

    RETURN_ON_BAD_kinetisI2cStatus(result);

    return I2C_OK;
}

unsigned int axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pRx, unsigned short rxLen)
{
    status_t result;
    if (conn_ctx == I3C0) {
        i3c_master_transfer_t masterXfer;

        masterXfer.slaveAddress   = addr >> 1; // the address of the NX
        masterXfer.direction      = kI3C_Read;
        masterXfer.busType        = kI3C_TypeI2C;
        masterXfer.subaddress     = 0x00;
        masterXfer.subaddressSize = 0;
        masterXfer.data           = pRx;
        masterXfer.dataSize       = rxLen;
        masterXfer.flags          = kI3C_TransferDefaultFlag;

        result = I3C_MasterTransferBlocking(I3C_MASTER, &masterXfer);
    }
    else {
        lpi2c_master_transfer_t masterXfer;
        memset(&masterXfer, 0, sizeof(masterXfer)); //clear values

        if (pRx == NULL || rxLen > MAX_DATA_LEN) {
            return I2C_FAILED;
        }

        masterXfer.slaveAddress   = addr >> 1; // the address of the NX
        masterXfer.direction      = kLPI2C_Read;
        masterXfer.subaddress     = 0;
        masterXfer.subaddressSize = 0;
        masterXfer.data           = pRx;
        masterXfer.dataSize       = rxLen;
        masterXfer.flags          = kLPI2C_TransferDefaultFlag;

        I2CM_TX();
        // DEBUG_PRINT_KINETIS_I2C("RD", result);
    }
    RETURN_ON_BAD_kinetisI2cStatus(result);
    return I2C_OK;
}

#endif /* FSL_FEATURE_SOC_I2C_COUNT */
