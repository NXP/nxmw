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
#include "ex_multiple_symm_auth.h"
#include "fsl_sss_nx_auth.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
static ex_sss_boot_ctx_t gex_multiple_symm_auth_ctx;

symm_auth_parameter_t ex_symmAuthparam = {
    0,
};

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_multiple_symm_auth_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    /* Here we demonstrate the creation of two sessions- in session 1, we create a file and write some data onto it, and in session 2, we read the data from the file created in session 1.
    *
    * The Parameters that we chose for this example are as follow:
    * fileNo = 4
    * fileOption = Nx_CommMode_FULL (Full mode of communication)
    * FileAR.Read = 0x1
    * FileAR.Write = 0x0
    * FileAR.ReadWrite = 0x0
    * FileAR.Change = no access
    * fileSize = 200 bytes
    *
    * Note- 1) The fileReadAccess condition of the file in session 2 shall be either of the following:
               - Same as the keyNo used in symmetric authentication in session 1,
                 for eg. if the keyId = 1 in session 1, then the fileReadAccess condition for reading the file in session 2 shall be Nx_AccessCondition_Auth_Required_0x1
               - Nx_AccessCondition_Free_Access
    *       2) The fileNo 1, 2 and 3 cannot be used, as there are some inbuilt static files
    *          present with these IDs.
    */
    sss_status_t status                         = kStatus_SSS_Fail;
    smStatus_t sm_status                        = SM_NOT_OK;
    ex_sss_boot_ctx_t ex_multiple_symm_auth_ctx = {0};
    ex_sss_boot_ctx_t *pCtx2                    = &ex_multiple_symm_auth_ctx;

    nx_connect_ctx_t *pConnectCtx2 = NULL;
    sss_session_t *pPfSession2     = NULL;
    sss_nx_session_t *pSession     = NULL;
    sss_nx_session_t *pSession2    = NULL;
    pPfSession2                    = &pCtx2->session;
    pConnectCtx2                   = &pCtx2->nx_open_ctx;

    uint8_t keyNo               = NX_KEY_MGMT_APP_KEY_ID_1;
    uint8_t fileNo              = 6;
    uint16_t isoFileID          = 7;
    uint8_t fileOption          = Nx_CommMode_FULL;
    uint8_t fileReadAccess      = Nx_AccessCondition_Auth_Required_0x1;
    uint8_t fileWriteAccess     = Nx_AccessCondition_Auth_Required_0x0;
    uint8_t fileReadWriteAccess = Nx_AccessCondition_Auth_Required_0x0;
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
    size_t i                              = 0;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx);
    pSession = (sss_nx_session_t *)&pCtx->session;

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

    nx_sesson_bind(&((sss_nx_session_t *)pSession)->s_ctx, pConnectCtx2);
    LOG_I("Bind session 1 to session 2");

    pConnectCtx2->connType         = pCtx->nx_open_ctx.connType;
    pConnectCtx2->portName         = pCtx->nx_open_ctx.portName;
    pConnectCtx2->i2cAddress       = pCtx->nx_open_ctx.i2cAddress;
    pConnectCtx2->skip_select_file = pCtx->nx_open_ctx.skip_select_file;

    status = nx_init_conn_context_symm_auth(
        pConnectCtx2, SSS_EX_NX_AUTH_MECH, SSS_EX_NX_SECURE_TUNNELING_MECH, keyNo, false);
    if (kStatus_SSS_Success != status) {
        LOG_E("nx_init_conn_context_symm_auth failed");
        goto cleanup;
    }
    status = nx_prepare_host_for_auth(&pCtx2->host_session, &pCtx2->host_ks, pConnectCtx2);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    LOG_I("Trying to open session 2");
    status = sss_session_open(pPfSession2, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Encrypted, pConnectCtx2);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    pSession2 = (sss_nx_session_t *)&pCtx2->session;

    /*Read data from file*/
    sm_status = nx_ReadData(&((sss_nx_session_t *)pSession2)->s_ctx,
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

    nx_sesson_unbind(&((sss_nx_session_t *)pPfSession2)->s_ctx);
    LOG_I("Unbind session 2");

    ex_sss_session_close(pCtx2);
    LOG_I("Session 2 close");

cleanup:

    if ((kStatus_SSS_Success == status) && (SM_OK == sm_status)) {
        LOG_I("ex_multiple_symm_auth Example Success !!!...");
    }
    else {
        LOG_E("ex_multiple_symm_auth Example Failed !!!...");
    }

    return status;
}
