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
#include "nx_apdu.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define MD_LEN_BYTES 32

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_nx_digest_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_nx_digest_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    smStatus_t status          = SM_NOT_OK;
    uint8_t input[]            = "HelloWorld";
    size_t inputLen            = strlen((const char *)input);
    sss_nx_session_t *pSession = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx);
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Running Message Digest Example (Using slots) ex_nx_md_using_slots.c");

    LOG_I("Do Digest");
    LOG_MAU8_I("input", input, inputLen);

    LOG_I("Digest will be written to static buffer 0 and 1");
    status = nx_CryptoRequest_SHA_Oneshot(&((sss_nx_session_t *)pSession)->s_ctx,
        kSE_DigestMode_SHA256,
        kSE_CryptoDataSrc_CommandBuf,
        input,
        inputLen,
        kSE_CryptoDataSrc_SB0,
        NULL,
        0);
    ENSURE_OR_GO_CLEANUP(status == SM_OK);

cleanup:
    if (SM_OK == status) {
        LOG_I("ex_nx_md_using_slots Example Success !!!...");
        return kStatus_SSS_Success;
    }
    else {
        LOG_E("ex_nx_md_using_slots Example Failed !!!...");
        return kStatus_SSS_Fail;
    }
}
