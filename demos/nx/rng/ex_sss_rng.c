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
/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */
#define RANDOM_LEN_BYTES 32
/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_random_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_random_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status               = kStatus_SSS_Fail;
    uint8_t rndData[RANDOM_LEN_BYTES] = {0};
    size_t rndDataLen                 = sizeof(rndData);
    sss_rng_context_t ctx_rng         = {0};

    LOG_I("Running Get Random Data Example ex_sss_rng.c");

    ENSURE_OR_GO_CLEANUP(NULL != pCtx);

    status = sss_rng_context_init(&ctx_rng, &pCtx->session /* Session */);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_rng_get_random(&ctx_rng, rndData, rndDataLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Get Random Data successful !!!");
    LOG_MAU8_I("Generated random data:", rndData, rndDataLen);

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sss_rng Example Success !!!...");
    }
    else {
        LOG_E("ex_sss_rng Example Failed !!!...");
    }
    if (ctx_rng.session != NULL) {
        sss_rng_context_free(&ctx_rng);
    }
    return status;
}
