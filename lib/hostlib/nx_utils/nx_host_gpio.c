/*
*
* Copyright 2023-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#include "nx_host_gpio.h"

#if defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC)
#include "smComPCSC.h"
#endif
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
#include "smComSerial.h"
#endif
#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
#include "smComT1oI2C.h"
#endif
#if defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
#include "gpio_nx.h"
#endif


#if SSS_HAVE_HOST_RASPBIAN

U16 nx_host_GPIOInit(void *conn_ctx, U8 gpioPIN, U8 setInOutDir) {
    unsigned int status = 0;
    status = gpio_export(gpioPIN);
    if (status == 0) {
        goto exit;
    }
    sleep(1);
    status = gpio_direction(gpioPIN, setInOutDir);
exit:
    return status;
}

U16 nx_host_GPIORead(void *conn_ctx, U8 gpioPIN, U8 *resp, U16 *respLen) {
    int status = 0;
    unsigned int resplocal = 0;
    if (NULL == resp || NULL == respLen) {
        goto exit;
    }
    status   = gpio_read(gpioPIN, &resplocal);
    *resp = (U8)(resplocal);
exit:
    return (U16)true;
}

U16 nx_host_GPIOClear(void *conn_ctx, U8 gpioPIN) {
    int status = 0;
    unsigned int value = 0;
    status  = gpio_write((int)gpioPIN, 0);
    return (U16)status;
}

U16 nx_host_GPIOSet(void *conn_ctx, U8 gpioPIN) {
    int status = 0;
    unsigned int value = 1;
    status  = gpio_write(gpioPIN, 1);
    return (U16)status;
}

U16 nx_host_GPIOClose(void *conn_ctx, U8 gpioPIN) {
    int status = 0;
    status = gpio_unexport(gpioPIN);
    return status;
}

#elif defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)

U16 nx_host_GPIOInit(void *conn_ctx, U8 gpioPIN, U8 setInOutDir)
{
    U32 status = 0;

    status   = smComVCom_GPIOInit(conn_ctx, gpioPIN, setInOutDir);
    return (U16)status;
}

U16 nx_host_GPIOSet(void *conn_ctx, U8 gpioPIN)
{
    U32 status = 0;

    status   = smComVCom_GPIOSet(conn_ctx, gpioPIN);
    return (U16)status;
}

U16 nx_host_GPIOClear(void *conn_ctx, U8 gpioPIN)
{
    U32 status = 0;

    status   = smComVCom_GPIOClear(conn_ctx, gpioPIN);
    return (U16)status;
}

U16 nx_host_GPIOToggle(void *conn_ctx, U8 gpioPIN)
{
    U32 status = 0;

    status   = smComVCom_GPIOToggle(conn_ctx, gpioPIN);
    return (U16)status;
}

U16 nx_host_GPIORead(void *conn_ctx, U8 gpioPIN, U8 *resp, U16 *respLen)
{
    U32 status = 0;
    U32 respLenLocal = 0;

    if (NULL == respLen) {
        goto exit;
    }
    respLenLocal = *respLen;

    status   = smComVCom_GPIORead(conn_ctx, gpioPIN, resp, &respLenLocal);
    if (respLenLocal <= UINT16_MAX) {
        *respLen = (U16)respLenLocal;
    } else {
        status = 0;
    }
exit:
    return (U16)status;
}

#endif // RJCT_VCOM