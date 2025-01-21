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
#include "nx_apdu.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_nx_cmac_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_nx_cmac_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    smStatus_t status = SM_NOT_OK;
    /* clang-format off */
    uint8_t key[16]   = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t input[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    /* clang-format on */
    uint8_t keySrc             = kSE_CryptoDataSrc_SB0;
    uint8_t inputSrc           = kSE_CryptoDataSrc_TB0;
    uint8_t output[16]         = {0};
    size_t outputLen           = sizeof(output);
    sss_nx_session_t *pSession = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx);
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Running CMAC Example (using Slots) ex_nx_cmac_using_slots.c");

    status = nx_CryptoRequest_Write_Internal_Buffer(&((sss_nx_session_t *)pSession)->s_ctx, keySrc, key, sizeof(key));
    ENSURE_OR_GO_CLEANUP(status == SM_OK);

    status =
        nx_CryptoRequest_Write_Internal_Buffer(&((sss_nx_session_t *)pSession)->s_ctx, inputSrc, input, sizeof(input));
    ENSURE_OR_GO_CLEANUP(status == SM_OK);

    LOG_I("Do CMAC");
    LOG_MAU8_I("input", input, sizeof(input));

    status = nx_CryptoRequest_AES_CMAC_Sign(&((sss_nx_session_t *)pSession)->s_ctx,
        Nx_MAC_Operation_OneShot,
        keySrc,
        16, /* Key length */
        inputSrc,
        NULL,
        sizeof(input),
        output,
        &outputLen);
    ENSURE_OR_GO_CLEANUP(status == SM_OK);

    LOG_MAU8_I("CMAC output", output, sizeof(output));

cleanup:
    if (SM_OK == status) {
        LOG_I("ex_nx_cmac_using_slots Example Success !!!...");
        return kStatus_SSS_Success;
    }
    else {
        LOG_E("ex_nx_cmac_using_slots Example Failed !!!...");
        return kStatus_SSS_Fail;
    }
}
