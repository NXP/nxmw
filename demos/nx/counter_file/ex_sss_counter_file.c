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
static ex_sss_boot_ctx_t gex_sss_fileMgnt;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_fileMgnt)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    /*In this example, we demonstrate how to create a counter file with given parameters.
    * Further, we also demonstrate how to increase counter and read data from the created file.
    *
    * The Parameters that we chose for this example are as follow:
    * fileNo = 0
    * fileOption = Nx_CommMode_FULL (Full mode of communication)
    * FileAR.Read = no access
    * FileAR.Write = no access
    * FileAR.ReadWrite = Nx_AccessCondition_Auth_Required_0x1
    * FileAR.Change = no access
    *
    * Note- The fileNo 1, 2 and 3 cannot be used, as there are some inbuilt static files
    *       present with these IDs.
    */
    sss_status_t status                   = kStatus_SSS_Fail;
    smStatus_t sm_status                  = SM_NOT_OK;
    sss_nx_session_t *pSession            = NULL;
    uint8_t fileNo                        = 0x15;
    uint32_t initCounterValue             = 0;
    uint8_t fileOption                    = Nx_CommMode_Plain;
    uint8_t fileReadAccess                = Nx_AccessCondition_No_Access;
    uint8_t fileWriteAccess               = Nx_AccessCondition_No_Access;
    uint8_t fileReadWriteAccess           = Nx_AccessCondition_Auth_Required_0x0;
    uint8_t fileChangeAccess              = Nx_AccessCondition_No_Access;
    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;
    bool fileExists                       = false;
    size_t i                              = 0;
    uint32_t counter                      = 0;
    size_t incrValue                      = 0;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Running File Management Example ex_sss_counter_file.c");

    // Check if the file exists
    sm_status = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
    ENSURE_OR_GO_CLEANUP(fIDListLen <= NX_FILE_ID_LIST_SIZE);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

    for (i = 0; i < fIDListLen; i++) {
        if (fileNo == fIDList[i]) {
            fileExists = true;
            break;
        }
    }

    if (fileExists == false) {
        /*Create counter file with the defined parameters*/
        sm_status = nx_CreateCounterFile(&((sss_nx_session_t *)pSession)->s_ctx,
            fileNo,
            initCounterValue,
            fileOption,
            fileReadAccess,
            fileWriteAccess,
            fileReadWriteAccess,
            fileChangeAccess);
        ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
        LOG_I("Counter File creation successful !!!");
    }

    /*Get counter from counter file*/
    sm_status = nx_GetFileCounters(&((sss_nx_session_t *)pSession)->s_ctx, fileNo, &counter, Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("Current counter value is 0x%x", counter);

    /*Increase counter*/
    incrValue = 3;
    sm_status = nx_IncrCounterFile(&((sss_nx_session_t *)pSession)->s_ctx, fileNo, incrValue, Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("Increase counter by 0x%zx", incrValue);

    /*Get counter from counter file*/
    sm_status = nx_GetFileCounters(&((sss_nx_session_t *)pSession)->s_ctx, fileNo, &counter, Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("Current counter value is 0x%x", counter);

cleanup:
    if (SM_OK == sm_status) {
        LOG_I("ex_sss_counter_file Example Success !!!...");
        status = kStatus_SSS_Success;
    }
    else {
        LOG_E("ex_sss_counter_file Example Failed !!!...");
        status = kStatus_SSS_Fail;
    }
    return status;
}
