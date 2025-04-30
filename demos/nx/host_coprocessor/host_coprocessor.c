/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <stddef.h>
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "sm_timer.h"
#include "phNxpEse_Api.h"
#include "platform.h"
#include "phNxpEse_internal.h"
#include "sm_timer.h"
#include "phNxpEseProto7816_3.h"
#include "host_copro_utils.h"
#include "host_copro_nx_apdu.h"
#include "host_copro_txn.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
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

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */
void hcp_board_setup();

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

void hcp_board_setup()
{
    platform_boot_direct();
}

int main()
{
    ESESTATUS status           = ESESTATUS_FAILED;
    smStatus_t retStatus       = SM_NOT_OK;
    const char *connectionType = NULL;

    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    uint8_t rspbuf[NX_MAX_BUF_SIZE_CMD]     = {0};

    // i2c protocol stack context
    phNxpEseProto7816_t i2c_ps1_ctx = {0};
    phNxpEseProto7816_t i2c_ps2_ctx = {0};

    phNxpEse_Context_t gnxpese1_ctxt = {0};
    phNxpEse_Context_t gnxpese2_ctxt = {0};

#if (defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947 == 1)) || \
    (defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153 == 1))
    gnxpese1_ctxt.pDevHandle = AX_I2CM;  //host co processor
    gnxpese2_ctxt.pDevHandle = AX_I2C0M; //NX
#endif

    void *conn1_ctx = &gnxpese1_ctxt;
    void *conn2_ctx = &gnxpese2_ctxt;

    size_t cmdDataBufLen  = 0;
    size_t rspbufLen      = sizeof(rspbuf);
    uint8_t tx_control[2] = {NX_HOST_COPRO_MSG_START, NX_HOST_COPRO_MSG_START2};
    uint32_t freemem      = 0;

    LOG_I("Running Host Coprocessor Example host_coprocessor.c");

    //setup the board
    hcp_board_setup();

    /* Selct application or card or picc*/
    LOG_I("Select Device 1 host coprocessor");
    status = nx_hcpSelectApplication(conn1_ctx, connectionType);
    if (status != ESESTATUS_SUCCESS) {
        LOG_E("nx_hcpSelectApplication failed");
        goto exit;
    }

    status = hcpContextSwitching(&i2c_ps1_ctx, &i2c_ps2_ctx);
    if (status != ESESTATUS_SUCCESS) {
        LOG_E("hcpContextSwitching failed");
        goto exit;
    }

    /* Selct application or card or picc*/
    LOG_I("Select Device 2 NX");
    status = nx_hcpSelectApplication(conn2_ctx, connectionType);
    if (status != ESESTATUS_SUCCESS) {
        LOG_E("nx_hcpSelectApplication failed");
        goto exit;
    }

    memcpy(cmdDataBuf, tx_control, sizeof(tx_control));
    cmdDataBufLen = sizeof(tx_control);

    LOG_I("Wait for Mutual authentication");
    status = nx_hcpEstablishSession(
        conn1_ctx, conn2_ctx, &i2c_ps1_ctx, &i2c_ps2_ctx, &cmdDataBuf[0], cmdDataBufLen, &rspbuf[0], &rspbufLen);
    if (status != SM_OK) {
        LOG_E("Mutual authentication failed");
        goto exit;
    }

    LOG_I("Mutual authentication is success");

    LOG_I("FreeMem Device 2");
    retStatus = nx_Freemem(conn1_ctx, conn2_ctx, &i2c_ps1_ctx, &i2c_ps2_ctx, &freemem);
    if (retStatus != SM_OK) {
        LOG_E("nx_Freemem failed");
        goto exit;
    }
    LOG_I("Available free memory: %u bytes", freemem);
    status = ESESTATUS_SUCCESS;

exit:

    /* Session close Commands */
    status = phNxpEse_close(conn1_ctx);
    if (status != ESESTATUS_SUCCESS) {
        LOG_E("phNxpEse_close (Device 1) Failed");
    }
    status = phNxpEse_close(conn2_ctx);
    if (status != ESESTATUS_SUCCESS) {
        LOG_E("phNxpEse_close (Device 2) Failed");
    }
    if (status == ESESTATUS_SUCCESS && retStatus == SM_OK) {
        LOG_I("nx_host_coprocessor Example Success !!!...");
    }
    else {
        LOG_I("nx_host_coprocessor Example failed !!!...");
    }
    return 0;
}
