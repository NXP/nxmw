/* Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "aws_demo.h"
#include "sm_types.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include "FreeRTOS.h"
#include "aws_iot_config.h"
#include "nxLog_msg.h"

/*******************************************************************
* MACROS
*******************************************************************/
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define AWS_TASK_PRIORITY (tskIDLE_PRIORITY)
#define AWS_TASK_STACK_SIZE 9000

#define LOGGING_TASK_PRIORITY (tskIDLE_PRIORITY + 1)
#define LOGGING_TASK_STACK_SIZE (250)
#define LOGGING_QUEUE_LENGTH (16)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

extern void awsPubSub_task(void *);

#include <nxLog_msg.h>
#include <ex_sss_boot.h>

static ex_sss_boot_ctx_t gex_sss_demo_boot_ctx;
ex_sss_boot_ctx_t *pex_sss_demo_boot_ctx = &gex_sss_demo_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_demo_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0
#define EX_SSS_BOOT_RTOS_STACK_SIZE 9000

/* ************************************************************************** */
/* Include "main()" with the platform specific startup code for NXMW examples */
/* which will call ex_sss_entry()                                             */
/* ************************************************************************** */
#include <ex_sss_main_inc.h>

/*******************************************************************************
 * Code
 ******************************************************************************/

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{

    awsPubSub_task((void *)pCtx);

    /* Should not reach this statement */
    for (;;)
        ;
}
