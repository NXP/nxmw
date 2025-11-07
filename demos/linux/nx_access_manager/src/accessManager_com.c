/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "nxLog_msg.h"
#include "fsl_sss_nx_apis.h"
#include "nx_secure_msg_apis.h"
#include "nx_apdu.h"
#include "nxEnsure.h"

#include "accessManager.h"
#include "accessManager_com.h"

#if defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC)
#include "smComPCSC.h"
#endif
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
#include "smComSerial.h"
#endif
#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
#include "smComT1oI2C.h"
#endif

smStatus_t amBreakDownAPDU(uint8_t *cmd,
    size_t cmdLen,
    tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t *cmdHeaderLen,
    uint8_t *cmdData,
    size_t *cmdDataLen,
    uint8_t *hasLe,
    uint8_t *isExtended)
{
    smStatus_t status = SM_ERR_WRONG_DATA;
    size_t localLen   = 0;
    size_t i          = 0;

    // Breakdown the received APDU into hdr, cmdHdr, cmdData, hasLe and isExtended
    if ((cmdLen - i < 4) || (cmdLen > NX_MAX_BUF_SIZE_CMD)) {
        return status;
    }
    hdr->hdr[0] = cmd[i++];
    hdr->hdr[1] = cmd[i++];
    hdr->hdr[2] = cmd[i++];
    hdr->hdr[3] = cmd[i++];

    switch (cmd[i]) {
    case 0:
        // Command has extended length represented by first 3 bytes
        i++;
        localLen = ((size_t)cmd[i++]) << 8;
        localLen += ((size_t)cmd[i++]);
        if ((MSG_HEADER_SIZE + MSG_EXTENDED_LENGTH_BYTES + localLen) > cmdLen) {
            LOG_E("Command buffer is smaller than expected");
            return status;
        }
        break;

    default:
        localLen = cmd[i++];
        if (MSG_HEADER_SIZE + MSG_SHORT_LENGTH_BYTES + localLen > cmdLen) {
            LOG_E("Command buffer is smaller than expected");
            return status;
        }
        break;
    }

    // Copy cmdHeader
    if (cmdLen - 2 < i) {
        return status;
    }

    localLen = ((size_t)cmd[i++]) << 8;
    localLen += ((size_t)cmd[i++]);

    if ((cmdLen < localLen) || ((cmdLen - localLen < i) || (localLen > *cmdHeaderLen))) {
        return status;
    }
    if (localLen) {
        memcpy(cmdHeader, &cmd[i], localLen);
    }
    i += localLen;
    *cmdHeaderLen = localLen;

    //Copy cmdData
    if (cmdLen - 2 < i) {
        return status;
    }
    localLen = ((size_t)cmd[i++]) << 8;
    localLen += ((size_t)cmd[i++]);

    if ((*cmdDataLen > NX_MAX_BUF_SIZE_CMD) || (localLen > *cmdDataLen)) {
        return status;
    }
    if ((cmdLen < localLen) || (cmdLen - localLen < i)) {
        return status;
    }
    if (localLen) {
        memcpy(cmdData, &cmd[i], localLen);
    }
    i += localLen;
    *cmdDataLen = localLen;

    // Copy hasLe and isExtended
    if (cmdLen - 2 < i) {
        return status;
    }
    *hasLe      = cmd[i++];
    *isExtended = cmd[i];
    status      = SM_OK;

    return status;
}

smStatus_t amTxRxAPDU(SeSession_t *pSessionCtx, U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen, nx_auth_type_t auth_type)
{
    smStatus_t txStatus                           = SM_NOT_OK;
    U32 status                                    = 0;
    U16 cmdLenLocal                               = 0;
    U32 respLenLocal                              = *respLen;
    size_t respBufLen                             = *respLen;
    tlvHeader_t hdr                               = {0};
    uint8_t cmdHeader[NX_MAX_BUF_SIZE_CMD_HEADER] = {0};
    size_t cmdHeaderLen                           = sizeof(cmdHeader);
    uint8_t cmdData[NX_MAX_BUF_SIZE_CMD]          = {0};
    size_t cmdDataLen                             = sizeof(cmdData);
    nx_ev2_comm_mode_t commMode                   = EV2_CommMode_PLAIN;
    uint8_t hasLe                                 = 0;
    uint8_t isExtended                            = 0;
    size_t i                                      = 0;
    U8 cmdByte                                    = 0;
    uint8_t option                                = 0;

    LOG_D("FN: %s", __FUNCTION__);

    txStatus = amBreakDownAPDU(cmd, cmdLen, &hdr, cmdHeader, &cmdHeaderLen, cmdData, &cmdDataLen, &hasLe, &isExtended);
    LOG_AU8_D(hdr.hdr, sizeof(tlvHeader_t));
    LOG_AU8_D(cmdHeader, cmdHeaderLen);
    LOG_AU8_D(cmdData, cmdDataLen);
    LOG_D("hasLe: %d", hasLe);
    LOG_D("isExtended: %d", isExtended);

    switch (auth_type) {
    case knx_AuthType_None:
        // Copy actual APDU in cmd buffer
        if ((MSG_SIZE - cmdHeaderLen) < cmdDataLen || ((MSG_SIZE - TLV_HEADER_SIZE) < cmdHeaderLen + cmdDataLen)) {
            return SM_NOT_OK;
        }

        cmdLenLocal = cmdLen;

        // Reset the command buffer
        memset(cmd, 0, cmdLen);
        // Copy the header of 4 bytes
        memcpy(cmd, hdr.hdr, TLV_HEADER_SIZE);
        i      = TLV_HEADER_SIZE;
        cmdLen = cmdHeaderLen + cmdDataLen; // Actual command length without Lc, Le & header

        // Lc + command
        if (cmdLen > 0) {
            if (isExtended == 1) {
                // Extended mode
                cmd[i++] = 0x00;
                cmd[i++] = 0xFFu & (cmdLen >> 8);
                cmd[i++] = 0xFFu & (cmdLen);
            }
            else {
                // Short mode
                cmd[i++] = (uint8_t)cmdLen;
            }
            ENSURE_OR_RETURN_ON_ERROR((i + cmdLen) <= NX_MAX_BUF_SIZE_CMD, SM_NOT_OK);
            memcpy(&cmd[4], cmdHeader, cmdHeaderLen);
            memcpy(&cmd[cmdHeaderLen + 4], cmdData, cmdDataLen);
            i += cmdHeaderLen + cmdDataLen;
        }
        if (hasLe) {
            ENSURE_OR_RETURN_ON_ERROR(i < (NX_MAX_BUF_SIZE_CMD - 1), SM_NOT_OK);
            cmd[i++] = 0x00;
            if (isExtended == 1) {
                if (cmdLen == 0) { // Lc = 0
                    ENSURE_OR_RETURN_ON_ERROR(i < (NX_MAX_BUF_SIZE_CMD - 1), SM_NOT_OK);
                    cmd[i++] = 0x00;
                    cmd[i++] = 0x00;
                }
                else {
                    ENSURE_OR_RETURN_ON_ERROR(i < (NX_MAX_BUF_SIZE_CMD), SM_NOT_OK);
                    cmd[i++] = 0x00;
                }
            }
        }
        cmdLen = i;

        LOG_MAU8_I("RAW APDU TX:", cmd, cmdLen);
        status = smCom_TransceiveRaw(pSessionCtx->conn_ctx, cmd, cmdLen, resp, &respLenLocal);
        if (status != SMCOM_OK) {
            LOG_E("smCom_TransceiveRaw failed!!");
            return SM_NOT_OK;
        }
        if (respLenLocal > UINT16_MAX) {
            LOG_E("respLenLocal cannot be greater than 2 bytes");
            return SM_NOT_OK;
        }
        *respLen = (U16)respLenLocal;
        break;

    case knx_AuthType_SYMM_AUTH:
    case knx_AuthType_SIGMA_I_Verifier:
    case knx_AuthType_SIGMA_I_Prover:
        cmdByte = hdr.hdr[1];
        option  = cmdHeader[0];
        status  = am_get_command_commMode(cmdByte, &commMode);
        if (status != SCP_OK) {
            txStatus = nx_get_comm_mode(pSessionCtx, Nx_CommMode_NA, cmdByte, &commMode, (void *)&option);
            if (txStatus != SM_OK) {
                LOG_E("Failed to get commMode");
                return (U16)status;
            }
        }
        LOG_D("commMode: %02x", commMode);

        txStatus = pSessionCtx->fp_TXn(pSessionCtx,
            &hdr,
            cmdHeader,
            cmdHeaderLen,
            cmdData,
            cmdDataLen,
            resp,
            &respBufLen,
            hasLe,
            isExtended,
            (void *)&commMode);
        *respLen = (U16)respBufLen;
        break;
    default:
        break;
    }

    return txStatus;
}

uint16_t am_get_command_commMode(uint8_t cmdByte, nx_ev2_comm_mode_t *CommMode)
{
    uint16_t ret = SCP_FAIL;

    ENSURE_OR_GO_EXIT(NULL != CommMode)

    switch (cmdByte) {
    case NX_INS_GET_CARDUID:
    case NX_INS_MGMT_CERT_REPO:
    case NX_INS_SET_CONFIG:
    case NX_INS_CHANGE_FILE_SETTING:
    case NX_INS_GET_CONFIG:
    case NX_INS_CHANGE_KEY:
    case NX_INS_GET_FILE_COUNTERS:
        *CommMode = EV2_CommMode_FULL;
        break;
    case NX_INS_GET_VERSION:
    case NX_INS_GET_KEY_VERSION:
    case NX_INS_GET_KEY_SETTINGS:
    case NX_INS_GET_ISO_FILE_IDS:
    case NX_INS_GET_FILE_IDS:
    case NX_INS_CREATE_STD_DATA_FILE:
    case NX_INS_CREATE_COUNTER_FILE:
    case NX_INS_GET_FILE_SETTINGS:
    case NX_INS_FREE_MEM:
    case NX_INS_ACTIVATE_CONFIG:
        *CommMode = EV2_CommMode_MAC;
        break;
    case NX_INS_ADDITIONAL_FRAME_REQ:
    case NX_INS_ISO_SELECT_FILE:
    case NX_INS_PROCESS_SM:
        *CommMode = (EV2_CommMode_PLAIN & 0x0F);
        break;
    default:
        goto exit;
    }
    ret = SCP_OK;
exit:
    return ret;
}