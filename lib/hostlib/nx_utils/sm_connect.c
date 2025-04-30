/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
* @file sm_connect.c
* @par Description
* Implementation of basic communication functionality between Host and NX.
*/

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sm_api.h"
#include "sm_apdu.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "sm_const.h"

/// @cond

//Also do select after opening the connection
#define OPEN_AND_SELECT 0

/// @endcond

#if (defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC))
#include "smComPCSC.h"
#endif
#if (defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM))
#include "smComSerial.h"
#endif
#if (defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0))
#include "smComT1oI2C.h"
#include "phNxpEse_Api.h"
#elif (defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM))
#include "smComSocket.h"
#endif

/// @cond Optional diagnostics functionality
#if SSS_HAVE_LOG_VERBOSE
#define FPRINTF(...) printf(__VA_ARGS__)
#else
#define FPRINTF(...)
#endif
/// @endcond

#define CLA_ISO7816 (0x00)                  //!< ISO7816-4 defined CLA byte
#define INS_GP_INITIALIZE_UPDATE (0x50)     //!< Global platform defined instruction
#define INS_GP_EXTERNAL_AUTHENTICATE (0x82) //!< Global platform defined instruction
#define INS_GP_SELECT (0xA4)                //!< Global platform defined instruction
#define INS_GP_PUT_KEY (0xD8)               //!< Global platform defined instruction
#define P2_NO_FCI (0x0C)                    //!< Global platform defined instruction

U16 nx_file_select(void *conn_ctx, const U8 *appletName, U16 appletNameLen);

#if (defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM))
U16 SM_RjctConnectVCOM(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *cip, U16 *cipLen)
{
    U32 status = 0;

    status = smComVCom_Open(conn_ctx, connectString);

    if (status == 0 || status == SMCOM_COM_ALREADY_OPEN) {
        if (conn_ctx == NULL) {
            status = smComVCom_GetCip(NULL, cip, cipLen);
            if (status == 0) {
                status = (U16)SM_Connect(NULL, commState, cip, cipLen);
                if (status != SMCOM_OK) {
                    SM_Close(NULL, 0);
                }
            }
            else {
                SM_Close(NULL, 0);
            }
        }
        else {
            status = smComVCom_GetCip(*conn_ctx, cip, cipLen);
            if (status == 0) {
                status = (U16)SM_Connect(*conn_ctx, commState, cip, cipLen);
            }
            else {
                SM_Close(NULL, 0);
            }
        }
    }
    else {
        if (NULL != cipLen) {
            *cipLen = 0;
        }
    }

    return (U16)status;
}
#endif // SSS_HAVE_SMCOM_VCOM

#if (defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC))
U16 SM_RjctConnectPCSC(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *cip, U16 *cipLen)
{
    U32 status = SMCOM_COM_FAILED;
    status     = smComPCSC_Open(connectString);

    if (status == SMCOM_OK) {
        if (conn_ctx == NULL) {
            status = (U16)SM_Connect(NULL, commState, cip, cipLen);
        }
        else {
            status = (U16)SM_Connect(*conn_ctx, commState, cip, cipLen);
        }
    }
    else {
        if (NULL != cipLen) {
            *cipLen = 0;
        }
    }

    return (U16)status;
}
#endif // SSS_HAVE_SMCOM_PCSC

#if (defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM))
U16 SM_RjctConnectJRCP_V1_AM(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *cip, U16 *cipLen)
{
    U32 status                        = SMCOM_COM_FAILED;
    U8 pIpAddrString[IP_ADDR_MAX_LEN] = {0};
    U16 portNo                        = 0;
    U8 i                              = 0; // Index for traversing connectString

    if (connectString == NULL) {
        LOG_E("Please provide IP address to connect to the JRCP_V1_AM server");
        return status;
    }

    // Extract IP address and port number from the connect string
    while (connectString[i] != '\0' && connectString[i] != ':') {
        i++;
    }
    if (connectString[i] != ':') {
        LOG_E(
            "Invalid IP address. Please provide IP address and port in the format <IP_ADDRESS>:<PORT_NO> as argument");
        return status;
    }

    // Length of the IP address should be at most one less than IP_ADDR_MAX_LEN
    // to allow termination of string with null character ('\0')
    if (i >= IP_ADDR_MAX_LEN) {
        LOG_E("Too long IP address");
        return status;
    }
    // Copy IP address in pIpAddrString and add null character to end the string
    memcpy(pIpAddrString, connectString, i);
    pIpAddrString[i] = '\0';
    i++;

    portNo = (U16)atoi(&connectString[i]);
    LOG_D("Connecting to IP address: %s, port no: %d", pIpAddrString, portNo);

    status = smComSocket_Open(conn_ctx, pIpAddrString, portNo, cip, cipLen);

    if (status == SMCOM_OK) {
        if (conn_ctx == NULL) {
            status = (U16)SM_Connect(NULL, commState, cip, cipLen);
        }
        else {
            status = (U16)SM_Connect(*conn_ctx, commState, cip, cipLen);
        }
    }
    else {
        if (NULL != cipLen) {
            *cipLen = 0;
        }
    }

    return (U16)status;
}
#endif
U16 SM_RjctConnect(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *cip, U16 *cipLen)
{
#if (defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM))
    bool is_vcom = FALSE;

    if (NULL == connectString) {
        is_vcom = FALSE;
    }
    else if (0 == strncmp("COM", connectString, sizeof("COM") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("\\\\.\\COM", connectString, sizeof("\\\\.\\COM") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("/tty/", connectString, sizeof("/tty/") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("/dev/tty", connectString, sizeof("/dev/tty") - 1)) {
        is_vcom = TRUE;
    }

    if (is_vcom) {
        return SM_RjctConnectVCOM(conn_ctx, connectString, commState, cip, cipLen);
    }
    else {
        LOG_W("Build is compiled for VCOM. connectString='%s' does not look like COMPort", connectString);
        LOG_W("e.g. connectString are COM3, \\\\.\\COM5, /dev/tty.usbmodem1432301, etc.");
    }
#elif (defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC))
    if (NULL != commState) {
        return SM_RjctConnectPCSC(conn_ctx, connectString, commState, cip, cipLen);
    }
#elif (defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM))
    if (NULL != commState) {
        return SM_RjctConnectJRCP_V1_AM(conn_ctx, connectString, commState, cip, cipLen);
    }
#else
    LOG_W(
        "Can not use connectString='%s' in the current build configuration.\n\tPlease select correct smCom interface "
        "and re-compile!\n",
        connectString);
#endif // SSS_HAVE_SMCOM_JRCP_V1_AM
    return ERR_NO_VALID_IP_PORT_PATTERN;
}

#if ((defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)) || \
     (defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC)) || \
     (defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM)))
#else
U16 SM_I2CConnect(void **conn_ctx, SmCommState_t *commState, U8 *cip, U16 *cipLen, const char *pConnString)
{
    U16 status = SMCOM_COM_FAILED;
#if (defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0))
    if (commState == NULL) {
        return status;
    }

    if (commState->sessionResume == 1) {
        status = smComT1oI2C_Resume(conn_ctx, pConnString);
    }
    else {
        status = smComT1oI2C_Init(conn_ctx, pConnString);
    }
#endif
    if (status != SMCOM_OK) {
        return status;
    }
    if (conn_ctx == NULL) {
        status = SM_Connect(NULL, commState, cip, cipLen);
        if (status != SW_OK) {
#if (defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0))
            phNxpEse_close(NULL);
#endif // SSS_HAVE_SMCOM_T1OI2C_GP1_0
        }
        return status;
    }
    else {
        status = SM_Connect(*conn_ctx, commState, cip, cipLen);
        if (status != SW_OK && *conn_ctx != NULL) {
#if (defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0))
            phNxpEse_close(*conn_ctx);
#endif // SSS_HAVE_SMCOM_T1OI2C_GP1_0
            *conn_ctx = NULL;
        }
        return status;
    }
}
#endif

/**
* Establishes the communication with the Security Module (SM) at the link level and
* selects the A71CH applet on the SM. The physical communication layer used (e.g. I2C)
* is determined at compilation time.
*
* @param[in,out] commState
* @param[in,out] cip
* @param[in,out] cipLen
*
* @retval ::SW_OK Upon successful execution
*/
U16 SM_Connect(void *conn_ctx, SmCommState_t *commState, U8 *cip, U16 *cipLen)
{
    U16 sw = ERR_COMM_ERROR;

#if !defined(IPC)
#ifdef APPLET_NAME
    unsigned char appletName[] = APPLET_NAME;
#endif // APPLET_NAME
    U16 uartBR = 0;
    U16 t1BR   = 0;
#endif

#ifdef TDA8029_UART
    U32 status = 0;
#endif

#if (defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0))
    sw = smComT1oI2C_Open(conn_ctx, ESE_MODE_NORMAL, 0x00, cip, cipLen);
#elif (defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC))
    if (cipLen != NULL) {
        *cipLen = 0;
    }
    sw = SMCOM_OK;
    AX_UNUSED_ARG(cip);
    AX_UNUSED_ARG(cipLen);
#elif (defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM))
    sw = SMCOM_OK;
#elif (defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM))
    if (cipLen != NULL) {
        *cipLen = 0;
    }
    sw = SMCOM_OK;
    AX_UNUSED_ARG(cip);
    AX_UNUSED_ARG(cipLen);
#endif

#if !defined(IPC)
    commState->param1         = t1BR;
    commState->param2         = uartBR;
    commState->hostLibVersion = (AX_HOST_LIB_MAJOR << 8) + AX_HOST_LIB_MINOR;
    commState->appletVersion  = 0xFFFF;
    commState->sbVersion      = 0xFFFF;

#ifdef APPLET_NAME
    if (sw == SMCOM_OK) {
        sw = ERR_COMM_ERROR;
        /* Select the applet */
        if (commState->select == SELECT_APPLICATION) {
            sw = nx_file_select(conn_ctx, (U8 *)&appletName, APPLET_NAME_LEN);
        }
        else {
            sw = SMCOM_OK;
        }

        if (sw == SW_FILE_NOT_FOUND) {
            // Applet can not be selected (most likely it is simply not installed)
            LOG_E("Can not select Applet=%s'", SE_NAME);
            LOG_MAU8_E("Failed (SW_FILE_NOT_FOUND) selecting Applet. ", appletName, APPLET_NAME_LEN);
            return sw;
        }
        else if (sw != SW_OK) {
            LOG_E("SM_CONNECT Failed.");
            sw = ERR_CONNECT_SELECT_FAILED;
        }
        else {
        }
    }
#endif /* Applet Name*/
#endif // !defined(IPC)
    return sw;
}

/**
 * Closes the communication with the Security Module
 * A new connection can be established by calling ::SM_Connect
 *
 * @param[in] mode Specific information that may be required on the link layer
 *
 * @retval ::SW_OK Upon successful execution
 */
U16 SM_Close(void *conn_ctx, U8 mode)
{
    U16 sw = ERR_COMM_ERROR;

#if (defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC))
    sw = smComPCSC_Close(mode);
#endif
#if (defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0))
    sw = smComT1oI2C_Close(conn_ctx, mode);
#endif
#if (defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM))
    AX_UNUSED_ARG(mode);
    sw = smComVCom_Close(conn_ctx);
#endif
#if (defined(SSS_HAVE_SMCOM_JRCP_V1_AM) && (SSS_HAVE_SMCOM_JRCP_V1_AM))
    AX_UNUSED_ARG(mode);
    AX_UNUSED_ARG(conn_ctx);
    sw = smComSocket_Close();
#endif
    smCom_DeInit();
    return sw;
}

/**
 * Send a select command to the card manager
 *
 * \param[in] appletName Pointer to a buffer containing the applet name.
 * \param[in] appletNameLen Length of the applet name.
 * \param[out] responseData Pointer to a buffer that will contain response data (excluding status word).
 * \param[in,out] responseDataLen IN: size of pResponse buffer passed as argument; OUT: Length of response data retrieved
 *
 * \retval ::SW_OK Upon successfull execution
 */
U16 nx_file_select(void *conn_ctx, const U8 *appletName, U16 appletNameLen)
{
    U16 rv                              = ERR_COMM_ERROR;
    U32 status                          = ERR_COMM_ERROR;
    uint8_t tx_buf[MAX_APDU_BUF_LENGTH] = {0};
    uint16_t tx_len;
    U8 responseData[256] = {0};
    U32 responseDataLen  = sizeof(responseData);
    ;

    ENSURE_OR_GO_CLEANUP(appletNameLen < 255);
    /* cla+ins+p1+p2+lc+appletNameLen+le */
    ENSURE_OR_GO_CLEANUP(sizeof(tx_buf) > (6u + appletNameLen));

    tx_buf[0] = CLA_ISO7816;
    tx_buf[1] = INS_GP_SELECT;
    tx_buf[2] = 4;
    tx_buf[3] = P2_NO_FCI;

    tx_len = 0   /* for indentation */
             + 1 /* CLA */
             + 1 /* INS */
             + 1 /* P1 */
             + 1 /* P2 */;
    if (appletNameLen > 0) {
        tx_buf[4] = (uint8_t)appletNameLen; // We have done ENSURE_OR_GO_CLEANUP(appletNameLen < 255);
        tx_len    = tx_len + 1              /* Lc */
                 + appletNameLen /* Payload */;
        memcpy(&tx_buf[5], appletName, appletNameLen);
        tx_buf[tx_len] = 0x0;
        tx_len         = tx_len + 1; /* Le */
    }
    else {
        tx_len = tx_len /* for indentation */
                 + 0 /* No Lc */;
    }

    status = smCom_TransceiveRaw(conn_ctx, tx_buf, tx_len, responseData, &responseDataLen);
    if (status == SW_OK && responseDataLen == 2) {
        rv = (U16)responseData[0];
        rv <<= 8;
        rv |= (U16)responseData[1];
    }

cleanup:
    return rv;
}
