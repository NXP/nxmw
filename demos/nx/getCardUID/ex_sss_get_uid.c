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
#include "nx_enums.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_get_uid_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_get_uid_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    sss_nx_session_t *pSession = NULL;

    uint8_t uidBuffer[10] = {0};
    size_t uidLen         = sizeof(uidBuffer);

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Running Get Card UID Example ex_sss_get_uid.c");

    LOG_I("Get Card UID");

    sm_status = nx_GetCardUID(&((sss_nx_session_t *)pSession)->s_ctx, uidBuffer, &uidLen);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

    LOG_I("Successful !!!");
    LOG_MAU8_I("Card UID", uidBuffer, uidLen);
cleanup:
    if (SM_OK == sm_status) {
        LOG_I("ex_sss_get_uid Example Success !!!...");
        status = kStatus_SSS_Success;
    }
    else {
        LOG_E("ex_sss_get_uid Example Failed !!!...");
        status = kStatus_SSS_Fail;
    }

    return status;
}
