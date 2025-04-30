/* Copyright 2020, 2023-2024 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include "smComSerial.h"
#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <paths.h>
#include <termios.h>
#include <sysexits.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include "smComSocket.h"
#include "nxLog_msg.h"
#include "inttypes.h"
#include "nxEnsure.h"
#include "sm_timer.h"

#define REMOTE_JC_SHELL_HEADER_LEN (4)
#define REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA (0x01)
#include "sm_apdu.h"
#define MAX_BUF_SIZE (MAX_APDU_BUF_LENGTH)
#define SETSCHEDPARAM_MAX_BUF_SIZE (150)

static int gfileDescriptor = -1;

static int smUartSetInterfaceAttrib(int fd, uint32_t speed);

U32 smComVCom_Open(void **vcom_ctx, const char *portname)
{
    char bufSetSchedParam[SETSCHEDPARAM_MAX_BUF_SIZE] = {0};
    char *pbufSetSchedParam                           = &bufSetSchedParam[0];
    size_t sizeSetSchedParam                          = SETSCHEDPARAM_MAX_BUF_SIZE;

    if (NULL == portname) {
        LOG_E("Invalid portname");
        goto error;
    }

    LOG_I("Opening %s", portname);

    gfileDescriptor = open(portname, O_RDWR | O_NOCTTY);
    LOG_I("gfileDescriptor = %d", gfileDescriptor);
    if (gfileDescriptor < 0) {
        LOG_E("error %d opening %s: %s\r\n", errno, portname, strerror_r(errno, bufSetSchedParam, sizeSetSchedParam));
        goto error;
    }
    if (0 == smUartSetInterfaceAttrib(gfileDescriptor, B115200)) {
        if (SMCOM_OK != smCom_Init(&smComVCom_Transceive, &smComVCom_TransceiveRaw)) {
            LOG_E("smCom_Init Failed");
            goto error;
        }
    }
    else {
        LOG_W("smUartSetInterfaceAttrib Failed");
        goto error;
    }
    return 0;

error:
    if (gfileDescriptor != -1) {
        close(gfileDescriptor);
    }

    return 1;
}

U32 smComVCom_Close(void *conn_ctx)
{
    U32 status = 1;

    if (0 != smComSocket_CloseFD(gfileDescriptor)) {
        goto exit;
    }
    status = 0;
exit:
    return status;
}

U32 smComVCom_GetCip(void *conn_ctx, U8 *pCip, U16 *cipLen)
{
    return smComSocket_GetCIPFD(gfileDescriptor, pCip, cipLen);
}

U32 smComVCom_Transceive(void *conn_ctx, apdu_t *pApdu)
{
    return smComSocket_TransceiveFD(gfileDescriptor, pApdu);
}

U32 smComVCom_TransceiveRaw(void *conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    return smComSocket_TransceiveRawFD(gfileDescriptor, pTx, txLen, pRx, pRxLen);
}

U32 smComVCom_GPIOInit(void *conn_ctx, U8 gpioPIN, U8 setInOutDir)
{
    return smComSocket_GPIOInitFD(gfileDescriptor, gpioPIN, setInOutDir);
}

U32 smComVCom_GPIOSet(void *conn_ctx, U8 gpioPIN)
{
    return smComSocket_GPIOSetFD(gfileDescriptor, gpioPIN);
}

U32 smComVCom_GPIOClear(void *conn_ctx, U8 gpioPIN)
{
    return smComSocket_GPIOClearFD(gfileDescriptor, gpioPIN);
}

U32 smComVCom_GPIOToggle(void *conn_ctx, U8 gpioPIN)
{
    return smComSocket_GPIOToggleFD(gfileDescriptor, gpioPIN);
}

U32 smComVCom_GPIORead(void *conn_ctx, U8 gpioPIN, U8 *pRx, U32 *pRxLen)
{
    return smComSocket_GPIOReadFD(gfileDescriptor, gpioPIN, pRx, pRxLen);
}

static int smUartSetInterfaceAttrib(int fd, uint32_t speed)
{
    struct termios SerialPortSettings; /* Create the structure */

    bzero(&SerialPortSettings, sizeof(SerialPortSettings));

    SerialPortSettings.c_cflag = CRTSCTS | CS8 | CLOCAL | CREAD;
    if (cfsetspeed(&SerialPortSettings, speed)) // Set  baud
    {
        LOG_W("cfsetspeed Failed");
    }

    SerialPortSettings.c_iflag     = IGNPAR;
    SerialPortSettings.c_oflag     = 0;
    SerialPortSettings.c_cc[VMIN]  = 1;
    SerialPortSettings.c_cc[VTIME] = 5;

    if (cfsetispeed(&SerialPortSettings, speed)) /* Set Read  Speed */
    {
        LOG_W("cfsetspeed Failed");
    }
    if (cfsetospeed(&SerialPortSettings, speed)) /* Set Write Speed */
    {
        LOG_W("cfsetspeed Failed");
    }
    //tcflush(fd, TCIFLUSH);
    if ((tcsetattr(fd, TCSANOW, &SerialPortSettings)) != 0) /* Set the attributes to the termios structure*/
    {
        LOG_W("Failed Setting attributes");
        return 1;
    }
    else {
        LOG_D("Attributes Set");
        return 0;
    }
}
