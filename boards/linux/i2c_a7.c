/*
 *
 * Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * MCIMX6UL-EVK / MCIMX8M-EVK board specific & Generic i2c code
 * @par History
 *
 **/
#include "i2c_a7.h"
#include <stdio.h>
#include <string.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <linux/version.h>
#include <errno.h>
#include <time.h>

/* Set NX_ENABLE_LEVEL_SHIFTER macro to 1
 * to enable level shifter
 */
#define NX_ENABLE_LEVEL_SHIFTER 0

#include "nxLog_msg.h"

static char* default_axSmDevice_name = "/dev/i2c-1";
static int default_axSmDevice_addr = 0x20;      // 7-bit address

#define DEV_NAME_BUFFER_SIZE 64

#if NX_ENABLE_LEVEL_SHIFTER
i2c_error_t i2c_level_shifter()
{
    int axSmDevice = 0;
    U32 dev_addr   = 0x20;
    unsigned long funcs;
    int nrWritten = -1;
    uint8_t txBuf[8] = {0};
    int txBufLen     = 0;

    // edit i2c bus level_shifter if different address
    static char* default_level_shifter_device = "/dev/i2c-11";

    // i2c file descriptor for second channel (DAC and IO expander).
    if ((axSmDevice = open(default_level_shifter_device, O_RDWR)) < 0)
    {
        LOG_E("failed to open i2c bus:%s\n", default_level_shifter_device);
        return I2C_FAILED;
    }

    if (ioctl(axSmDevice, I2C_SLAVE, dev_addr) < 0)
    {
        LOG_E("I2C driver failed setting address\n");
        close(axSmDevice);
        return I2C_FAILED;
    }

    // clear PEC flag
    if (ioctl(axSmDevice, I2C_PEC, 0) < 0)
    {
        LOG_E("I2C driver: PEC flag clear failed\n");
        close(axSmDevice);
        return I2C_FAILED;
    }

    // Query functional capacity of I2C driver
    if (ioctl(axSmDevice, I2C_FUNCS, &funcs) < 0)
    {
        LOG_E("Cannot get i2c adapter functionality\n");
        close(axSmDevice);
        return I2C_FAILED;
    }

    // outPort IC2
    txBuf[0]  = 0x01;
    txBuf[1]  = 0x10;
    txBufLen  = 2;
    nrWritten = write(axSmDevice, txBuf, txBufLen);
    if (nrWritten < 0 || (nrWritten != txBufLen))
    {
        LOG_E("Failed writing data at line %d. (nrWritten=%d).\n", __LINE__, nrWritten);
        return I2C_FAILED;
    }

    //Config Port Register IC2
    txBuf[0]  = 0x03;
    txBuf[1]  = 0x88;
    txBufLen  = 2;
    nrWritten = write(axSmDevice, txBuf, txBufLen);
    if (nrWritten < 0 || (nrWritten != txBufLen))
    {
        LOG_E("Failed writing data at line %d. (nrWritten=%d).\n", __LINE__, nrWritten);
        return I2C_FAILED;
    }

    dev_addr = 0x21;
    if (ioctl(axSmDevice, I2C_SLAVE, dev_addr) < 0)
    {
        LOG_E("I2C driver failed setting address\n");
        close(axSmDevice);
        return I2C_FAILED;
    }

    //set up port direction
    txBuf[0]  = 0x01;
    txBuf[1]  = 0x7C;
    txBufLen  = 2;
    nrWritten = write(axSmDevice, txBuf, txBufLen);
    if (nrWritten < 0 || (nrWritten != txBufLen))
    {
        LOG_E("Failed writing data at line %d. (nrWritten=%d).\n", __LINE__, nrWritten);
        return I2C_FAILED;
    }

    //sets up I2C+IO1+IO2 to 1k Pullup,
    txBuf[0]  = 0x03;
    txBuf[1]  = 0x03;
    txBufLen  = 2;
    nrWritten = write(axSmDevice, txBuf, txBufLen);
    if (nrWritten < 0 || (nrWritten != txBufLen))
    {
        LOG_E("Failed writing data at line %d. (nrWritten=%d).\n", __LINE__, nrWritten);
        return I2C_FAILED;
    }

    dev_addr = 0x61;
    if (ioctl(axSmDevice, I2C_SLAVE, dev_addr) < 0)
    {
        LOG_E("I2C driver failed setting address\n");
        close(axSmDevice);
        return I2C_FAILED;
    }

    // 1.7V LevelShifter clamp
    txBuf[0]  = 0x00;
    txBuf[1]  = 0x0B;
    txBuf[2]  = 0x33;
    txBufLen  = 3;
    nrWritten = write(axSmDevice, txBuf, txBufLen);
    if (nrWritten < 0 || (nrWritten != txBufLen))
    {
        LOG_E("Failed writing data at line %d. (nrWritten=%d).\n", __LINE__, nrWritten);
        return I2C_FAILED;
    }

    //power down -> reset
    txBuf[0]  = 0x08;
    txBuf[1]  = 0x00;
    txBuf[2]  = 0x00;
    txBufLen  = 3;
    nrWritten = write(axSmDevice, txBuf, txBufLen);
    if (nrWritten < 0 || (nrWritten != txBufLen))
    {
        LOG_E("Failed writing data at line %d. (nrWritten=%d).\n", __LINE__, nrWritten);
        return I2C_FAILED;
    }

    // wait
    //#   define WAIT_UNTIL_VCC_DISCHARGED_MS     1000
    usleep(1000);

    // levelshifter 1.8V
    txBuf[0]  = 0x08;
    txBuf[1]  = 0x05;
    txBuf[2]  = 0xEF;
    nrWritten = write(axSmDevice, txBuf, txBufLen);
    if (nrWritten < 0 || (nrWritten != txBufLen)) {
        LOG_E("Failed writing data at line %d. (nrWritten=%d).\n", __LINE__, nrWritten);
        return I2C_FAILED;
    }

    close(axSmDevice);
    return I2C_OK;
}
#endif

/**
* Opens the communication channel to I2C device
*/
i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName)
{
    unsigned long funcs = 0;
    int axSmDevice                  = 0;
    char *pdev_name                 = NULL;
    char *pdev_addr_str             = NULL;
    U32 dev_addr                    = 0x00;
    char temp[DEV_NAME_BUFFER_SIZE] = {
        0,
    };

#if NX_ENABLE_LEVEL_SHIFTER
    if (I2C_OK != i2c_level_shifter())
    {
        LOG_I("Error in i2c_level_shifter \n");
        return I2C_FAILED;
    }
#endif

    if (pDevName != NULL && (strcasecmp("none", pDevName) != 0))
    {
        if ((strlen(pDevName) + 1) < DEV_NAME_BUFFER_SIZE) {
            memcpy(temp, pDevName, strlen(pDevName));
            temp[strlen(pDevName)] = '\0';
        }
        else {
            LOG_E("Connection string passed as argument is too long (%d).", strlen(pDevName));
            LOG_I("Pass i2c device address in the format <i2c_port>:<i2c_addr(optional. Default 0x48)>.");
            LOG_I("Example ./example /dev/i2c-1:0x48 OR ./example /dev/i2c-1");
        }

        pdev_name = strtok(temp, ":");
        if (pdev_name == NULL) {
            perror("Invalid connection string");
            LOG_I("Pass i2c device address in the format <i2c_port>:<i2c_addr(optional. Default 0x48)>.");
            LOG_I("Example ./example /dev/i2c-1:0x48 OR ./example /dev/i2c-1");
            return I2C_FAILED;
        }

        pdev_addr_str = strtok(NULL, ":");
        if (pdev_addr_str != NULL) {
            dev_addr = strtol(pdev_addr_str, NULL, 0);
        }
        else {
            dev_addr = default_axSmDevice_addr;
        }
    }
    else {
        pdev_name = default_axSmDevice_name;
        dev_addr  = default_axSmDevice_addr;
    }

    LOG_D("I2CInit: opening %s\n", pdev_name);

    if ((axSmDevice = open(pdev_name, O_RDWR)) < 0) {
        LOG_E("opening failed...");
        perror("Failed to open the i2c bus");
        LOG_I("Pass i2c device address in the format <i2c_port>:<i2c_addr(optional. Default 0x48)>.");
        LOG_I("Example ./example /dev/i2c-1:0x48 OR ./example /dev/i2c-1");
        return I2C_FAILED;
    }

    if (ioctl(axSmDevice, I2C_SLAVE, dev_addr) < 0) {
        LOG_E("I2C driver failed setting address\n");
    }

    // clear PEC flag
    if (ioctl(axSmDevice, I2C_PEC, 0) < 0) {
        LOG_E("I2C driver: PEC flag clear failed\n");
    }
    else {
        LOG_D("I2C driver: PEC flag cleared\n");
    }

    // Query functional capacity of I2C driver
    if (ioctl(axSmDevice, I2C_FUNCS, &funcs) < 0) {
        LOG_E("Cannot get i2c adapter functionality\n");
        close(axSmDevice);
        return I2C_FAILED;
    }
    else {
        if (funcs & I2C_FUNC_I2C) {
            LOG_D("I2C driver supports plain i2c-level commands.\n");
        }
        else {
            LOG_E("I2C driver CANNOT support plain i2c-level commands!\n");
            close(axSmDevice);
            return I2C_FAILED;
        }
    }

    *conn_ctx = malloc(sizeof(int));
    if (*conn_ctx == NULL) {
        LOG_E("I2C driver: Memory allocation failed!\n");
        close(axSmDevice);
        return I2C_FAILED;
    }
    else {
        *(int *)(*conn_ctx) = axSmDevice;
        return I2C_OK;
    }
}

/**
* Closes the communication channel to I2C device
*/
void axI2CTerm(void *conn_ctx, int mode)
{
    AX_UNUSED_ARG(mode);
    // printf("axI2CTerm (enter) i2c device =  %d\n", *(int*)(conn_ctx));
    if (conn_ctx != NULL) {
        if (close(*(int *)(conn_ctx)) != 0) {
            LOG_E("Failed to close i2c device %d.\n", *(int *)(conn_ctx));
        }
        else {
            LOG_D("Close i2c device %d.\n", *(int *)(conn_ctx));
        }
        free(conn_ctx);
    }
    // printf("axI2CTerm (exit)\n");
    return;
}

#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
i2c_error_t axI2CWrite(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pTx, unsigned short txLen)
{
    int nrWritten  = -1;
    i2c_error_t rv = I2C_FAILED;
    int axSmDevice = *(int *)conn_ctx;
#ifdef LOG_I2C
    int i = 0;
#endif

    if (pTx == NULL || txLen > MAX_DATA_LEN) {
        return I2C_FAILED;
    }

    if (bus != I2C_BUS_0) {
        LOG_E("axI2CWrite on wrong bus %x (addr %x)\n", bus, addr);
    }
    LOG_MAU8_D("TX (axI2CWrite) > ", pTx, txLen);
    nrWritten = write(axSmDevice, pTx, txLen);
    if (nrWritten < 0) {
        LOG_E("Failed writing data at line %d. (nrWritten=%d).\n", __LINE__, nrWritten);
        rv = I2C_FAILED;
    }
    else {
        if (nrWritten == txLen) // okay
        {
            rv = I2C_OK;
        }
        else {
            rv = I2C_FAILED;
        }
    }
    LOG_D("Done with rv = %02x ", rv);

    return rv;
}
#endif // SSS_HAVE_SMCOM_T1OI2C_GP1_0


#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
i2c_error_t axI2CRead(void *conn_ctx, unsigned char bus, unsigned char addr, unsigned char *pRx, unsigned short rxLen)
{
    int nrRead     = -1;
    i2c_error_t rv = I2C_FAILED;
    int axSmDevice = -1;

    if ((conn_ctx == NULL) || (pRx == NULL) || (rxLen > MAX_DATA_LEN)) {
        return I2C_FAILED;
    }
    axSmDevice = *(int *)conn_ctx;

    if (bus != I2C_BUS_0) {
        LOG_E("axI2CRead on wrong bus %x (addr %x)\n", bus, addr);
    }

    nrRead = read(axSmDevice, pRx, rxLen);
    if (nrRead < 0) {
        //LOG_E("Failed Read data (nrRead=%d).\n", nrRead);
        rv = I2C_FAILED;
    }
    else {
        if (nrRead == rxLen) // okay
        {
            rv = I2C_OK;
        }
        else {
            rv = I2C_FAILED;
        }
    }
    LOG_D("Done with rv = %02x ", rv);
    LOG_MAU8_D("RX (axI2CRead): ",pRx,rxLen);
    return rv;
}
#endif // SSS_HAVE_SMCOM_T1OI2C_GP1_0
