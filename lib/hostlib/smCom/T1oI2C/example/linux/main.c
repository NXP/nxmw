/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <stddef.h>
#include "phEseTypes.h"
#include "phEseStatus.h"
#include "phNxpEse_Api.h"

#if defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED)
#include "platform.h"
#else
#define PRINTF printf
#endif

int main()
{
    void *conn_ctx        = NULL;
    uint8_t cip[100]      = {0};
    uint16_t cipLen       = sizeof(cip);
    uint8_t freememBuf[3] = {0};
    uint32_t freememsize  = 0;

    ESESTATUS status               = ESESTATUS_FAILED;
    phNxpEse_initParams initParams = {0};
    initParams.initMode            = ESE_MODE_NORMAL;

    phNxpEse_data AtrRsp    = {0};
    phNxpEse_data pCmdTrans = {0};
    phNxpEse_data pRspTrans = {0};

    uint8_t rx_buffer[256] = {0};

    /* Selct file command */
    uint8_t select_file[] = {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00};

    /* Get free memory command APDU */
    uint8_t getFreeMem_cmd[] = {0x90, 0x6E, 0x00, 0x00, 0x00, 0x00, 0x00};
#if defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED)
    platform_boot_direct();
#endif
    /* T=1oi2c open session */
    status = phNxpEse_open(conn_ctx, initParams, NULL);
    if (status != ESESTATUS_SUCCESS) {
        PRINTF("phNxpEse_open Failed\n\r");
        goto exit;
    }

    AtrRsp.len    = cipLen;
    AtrRsp.p_data = cip;
    status        = phNxpEse_init(conn_ctx, initParams, &AtrRsp);
    if (status != ESESTATUS_SUCCESS) {
        PRINTF("phNxpEse_init failed\n\r");
        goto exit;
    }

    /* Send select file command */
    pCmdTrans.len    = sizeof(select_file);
    pCmdTrans.p_data = select_file;
    pRspTrans.len    = sizeof(rx_buffer);
    pRspTrans.p_data = rx_buffer;
    status           = phNxpEse_Transceive(conn_ctx, &pCmdTrans, &pRspTrans);
    if (status != ESESTATUS_SUCCESS) {
        PRINTF("phNxpEse_Transceive Failed\n\r");
        goto exit;
    }

    /* Send get free memory command */
    pCmdTrans.len    = sizeof(getFreeMem_cmd);
    pCmdTrans.p_data = getFreeMem_cmd;
    pRspTrans.len    = sizeof(rx_buffer);
    pRspTrans.p_data = rx_buffer;

    status = phNxpEse_Transceive(conn_ctx, &pCmdTrans, &pRspTrans);
    if (status != ESESTATUS_SUCCESS) {
        PRINTF("phNxpEse_Transceive Failed\n\r");
        goto exit;
    }

    memcpy(freememBuf, rx_buffer, 3);
    freememsize = (uint32_t)((freememBuf[2] << 16) | (freememBuf[1] << 8) | freememBuf[0]);

    PRINTF("Available free memory: %lu bytes\n\r", freememsize);

exit:

    /* Session close Commands */
    status = phNxpEse_close(conn_ctx);
    if (status != ESESTATUS_SUCCESS) {
        PRINTF("phNxpEse_close Failed\n\r");
    }

    if (status == ESESTATUS_SUCCESS) {
        PRINTF("ex_t1oi2c Example Success !!!...\n\r");
    }
    else {
        PRINTF("ex_t1oi2c Example Failed !!!...\n\r");
    }
}