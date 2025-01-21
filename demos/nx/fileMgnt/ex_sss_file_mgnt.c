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
    /*In this example, we demonstrate how to create a standard data file with given parameters.
    * Further, we also demonstrate how to read and write data onto the created file.
    *
    * The Parameters that we chose for this example are as follow:
    * fileNo = 0
    * fileOption = Nx_CommMode_FULL (Full mode of communication)
    * FileAR.Read = no access
    * FileAR.Write = no access
    * FileAR.ReadWrite = 0x1
    * FileAR.Change = no access
    * fileSize = 200 bytes
    *
    * Note- The fileNo 1, 2 and 3 cannot be used, as there are some inbuilt static files
    *       present with these IDs.
    */
    LOG_I("Running File Management Example ex_sss_file_mgnt.c");
    sss_status_t status         = kStatus_SSS_Fail;
    sss_nx_session_t *pSession  = NULL;
    smStatus_t sm_status        = SM_NOT_OK;
    uint8_t fileNo              = 0;
    uint16_t isoFileID          = 1;
    size_t i                    = 0;
    uint8_t fileOption          = Nx_CommMode_FULL;
    uint8_t fileReadAccess      = Nx_AccessCondition_No_Access;
    uint8_t fileWriteAccess     = Nx_AccessCondition_No_Access;
    uint8_t fileReadWriteAccess = Nx_AccessCondition_Auth_Required_0x1;
    uint8_t fileChangeAccess    = Nx_AccessCondition_No_Access;
    uint8_t fileSize            = 200; // file of size 200 bytes

    uint8_t writeData[] = "Hello World!";
    size_t writeOffset  = 0;
    size_t writeDataLen = strlen((const char *)writeData) - writeOffset;

    uint8_t readData[50] = {0};
    size_t readDataLen   = sizeof(readData);
    size_t readOffset    = 0;

    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;
    bool fileExists                       = false;

    /*Create file with the defined parameters*/

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    pSeSession_t session_ctx = &((sss_nx_session_t *)pSession)->s_ctx;
    if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        if (session_ctx->ctx.pdynSymmAuthCtx != NULL) {
            LOG_W("fileReadWriteAccess value is overwritten in the example");
            fileReadWriteAccess = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
        }
        else {
            LOG_E("Invalid symm auth context !!!");
        }
    }

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
        sm_status = nx_CreateStdDataFile(&((sss_nx_session_t *)pSession)->s_ctx,
            fileNo,
            isoFileID,
            fileOption,
            fileSize,
            fileReadAccess,
            fileWriteAccess,
            fileReadWriteAccess,
            fileChangeAccess);
        ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
        LOG_I("Standard Data File creation successful !!!");
    }
    else {
        LOG_I("Standard Data File already exist !!!");
    }

    /*Write data to file*/
    sm_status = nx_WriteData(
        &((sss_nx_session_t *)pSession)->s_ctx, fileNo, writeOffset, writeData, writeDataLen, Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("File write successful !!!");

    /*Read data from file*/
    sm_status = nx_ReadData(&((sss_nx_session_t *)pSession)->s_ctx,
        fileNo,
        readOffset,
        readDataLen,
        readData,
        &readDataLen,
        Nx_CommMode_NA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

    if (0 != memcmp(writeData, readData, writeDataLen)) {
        LOG_E("The written and read data are not the same !!!");
        goto cleanup;
    }
    LOG_I("File read successful !!!");

cleanup:
    if (SM_OK == sm_status) {
        LOG_I("ex_sss_file_mgnt Example Success !!!...");
        status = kStatus_SSS_Success;
    }
    else {
        LOG_E("ex_sss_file_mgnt Example Failed !!!...");
        status = kStatus_SSS_Fail;
    }
    return status;
}
