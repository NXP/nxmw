/* Copyright 2018, 2020, 2022-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "sm_types.h"
#include "windows.h"
#include <stdlib.h>
#include <stdio.h>
#include "smComSerial.h"
#include "WinDef.h"
#include "WinBase.h"
#include "string.h"
#include <assert.h>
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#define REMOTE_JC_SHELL_HEADER_LEN (4)
#define REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA (0x01)
#include "sm_apdu.h"
#define MAX_BUF_SIZE (MAX_APDU_BUF_LENGTH)

#include "nxLog_msg.h"
#include "nxEnsure.h"

#define MTY_CIP 0x00
#define MTY_CLOSE 0x03
#define MTY_GPIO_PIN_INIT 0x04
#define MTY_GPIO_PORT_SET 0x05
#define MTY_GPIO_PORT_CLEAR 0x06
#define MTY_GPIO_PORT_TOGGLE 0x07
#define MTY_GPIO_PIN_READ 0x08
#define NAD 0x00

static U8 Header[2] = {0x01, 0x00};
static U8 sockapdu[MAX_BUF_SIZE];
static U8 response[MAX_BUF_SIZE];
static U8 *pCmd = (U8 *)&sockapdu;
static U8 *pRsp = (U8 *)&response;

static HANDLE gpComHandle = INVALID_HANDLE_VALUE;

static void escapeComPortName(char pOutPortName[20], const char *iPortName)
{
    ENSURE_OR_GO_EXIT(iPortName != NULL);
    ENSURE_OR_GO_EXIT(strlen(iPortName) < 20);
    memcpy(pOutPortName, iPortName, strlen(iPortName) + 1 /*NULL termination*/);
    if (0 == _strnicmp(iPortName, "COM", 3)) {
        long number = atol(&iPortName[3]);
        if (number > 4) {
            ENSURE_OR_GO_EXIT((_snprintf(pOutPortName, 20, "\\\\.\\%s", iPortName)) >= 0);
        }
    }
    else {
        ENSURE_OR_GO_EXIT((_snprintf(pOutPortName, 20, "%s", iPortName)) >= 0);
    }
exit:
    return;
}

U32 smComVCom_Open(void **vcom_ctx, const char *pComPortString)
{
    U32 status = 0;
    COMMTIMEOUTS cto;
    char escaped_port_name[20] = {0};
    static HANDLE pComHandle   = INVALID_HANDLE_VALUE;
    pComHandle                 = gpComHandle;

#ifdef UNICODE
    wchar_t wPortName[20] = {0};
#endif
    /* Prepare CTO structure */
    cto.ReadTotalTimeoutConstant    = 500;
    cto.ReadTotalTimeoutMultiplier  = 0;
    cto.ReadIntervalTimeout         = 10;
    cto.WriteTotalTimeoutConstant   = 0;
    cto.WriteTotalTimeoutMultiplier = 0;

    escapeComPortName(escaped_port_name, pComPortString);

    printf("Opening COM Port '%s'\n", escaped_port_name);

    if (pComHandle != INVALID_HANDLE_VALUE) {
        printf("\n Already  COM Port Open \n ");
        if (vcom_ctx != NULL) {
            *vcom_ctx = pComHandle;
        }
        return SMCOM_COM_ALREADY_OPEN;
    }

#ifdef UNICODE
    mbstowcs(wPortName, escaped_port_name, sizeof(wPortName) / sizeof(wPortName[0]));
    pComHandle = CreateFile(wPortName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
#else
    pComHandle = CreateFile(escaped_port_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
#endif

    status = GetLastError();

    if (status == ERROR_SUCCESS) {
        status = smComVCom_SetState(pComHandle);

        if (status == 0) {
            if (SetCommTimeouts(pComHandle, &cto) == false) {
                status = 1;
            }
        }
    }
    else if (ERROR_FILE_NOT_FOUND == status) {
        printf("ERROR! Failed opening '%s'. ERROR=ERROR_FILE_NOT_FOUND\n", pComPortString);
    }
    else if (ERROR_ACCESS_DENIED == status) {
        printf("ERROR! Failed opening '%s'. ERROR=ERROR_ACCESS_DENIED\n", pComPortString);
    }
    else if (pComHandle == INVALID_HANDLE_VALUE) {
        printf("ERROR! Failed opening '%s'. ERROR=%X\n", escaped_port_name, status);
    }

    if (vcom_ctx == NULL) {
        gpComHandle = pComHandle;
    }
    else {
        *vcom_ctx   = pComHandle;
        gpComHandle = pComHandle;
    }
    return status;
}

U32 smComVCom_SetState(void *conn_ctx)
{
    U32 ret = 1;
    DCB dcb;
    memset(&dcb, 0, sizeof(dcb));
    HANDLE pComHandle = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;

    dcb.DCBlength         = sizeof(DCB);
    dcb.BaudRate          = 115200;
    dcb.fBinary           = true;
    dcb.fParity           = false;
    dcb.fOutxCtsFlow      = false;
    dcb.fOutxDsrFlow      = false;
    dcb.fDtrControl       = DTR_CONTROL_DISABLE;
    dcb.fDsrSensitivity   = false;
    dcb.fTXContinueOnXoff = true;
    dcb.fOutX             = false;
    dcb.fInX              = false;
    dcb.fErrorChar        = false;
    dcb.fNull             = false;
    dcb.fRtsControl       = RTS_CONTROL_DISABLE;
    dcb.fAbortOnError     = false;
    dcb.XonLim            = 0;
    dcb.XoffLim           = 0;
    dcb.ByteSize          = 8;
    dcb.Parity            = NOPARITY;
    dcb.StopBits          = ONESTOPBIT;

    if (SetCommState(pComHandle, &dcb) == false) {
        goto exit;
    }
    else {
        EscapeCommFunction(pComHandle, SETDTR);
        if (SMCOM_OK != smCom_Init(&smComVCom_Transceive, &smComVCom_TransceiveRaw)) {
            goto exit;
        }
        ret = 0;
    }
exit:
    return ret;
}

U32 smComVCom_GetCip(void *conn_ctx, U8 *pCip, U16 *cipLen)
{
    U32 rc             = 1;
    HANDLE pComHandle  = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;
    U32 expectedLength = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    DWORD WrittenLen   = 0;
    U8 status          = 0;

    // wait 256 ms
    U8 cipCmd[4] = {MTY_CIP, NAD, 0x00, 0x00};

    ENSURE_OR_GO_EXIT(pCip != NULL);
    ENSURE_OR_GO_EXIT(cipLen != NULL);

    LOG_MAU8_D("Get CIP", cipCmd, sizeof(cipCmd));

    status = WriteFile(pComHandle, cipCmd, sizeof(cipCmd), &WrittenLen, NULL);
    if ((status == 0) || (WrittenLen != sizeof(cipCmd))) {
        goto exit;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length
    ENSURE_OR_GO_EXIT(expectedLength <= *cipLen);

    while (totalReceived < expectedLength) {
        U32 maxCommLength  = 0;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        ENSURE_OR_GO_EXIT(maxCommLength <= ((*cipLen) - totalReceived));
        status = ReadFile(pComHandle, (char *)&pCip[totalReceived], maxCommLength, &numBytesRead, NULL);
        ENSURE_OR_GO_EXIT(numBytesRead <= INT32_MAX);
        if (status == 0) {
            if (fprintf(stderr, "Client: recv() failed: error %i.\n", numBytesRead) < 0) {
                LOG_E("Error in logging error to stderr");
            }
            goto exit;
        }
        else {
            totalReceived += numBytesRead;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pCip[2] << 8) | (pCip[3]))));
            expectedLength += ((pCip[2] << 8) | (pCip[3]));
            lengthReceived = 1;
        }
    }
    LOG_AU8_D(pCip, totalReceived);

    totalReceived -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    ENSURE_OR_GO_EXIT(*cipLen >= REMOTE_JC_SHELL_HEADER_LEN + totalReceived);
    memmove(pCip, pCip + 4, totalReceived);

    *cipLen = (U16)totalReceived;
    rc      = 0;
exit:
    return rc;
}

U32 smComVCom_Transceive(void *conn_ctx, apdu_t *pApdu)
{
#if defined(LOG_SOCK)
    int i = 0;
#endif
    U32 txLen          = 0;
    U32 expectedLength = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    U8 status          = 0;
    DWORD WrittenLen   = 0;
    U32 rv             = SMCOM_SND_FAILED;
    HANDLE pComHandle  = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;

    ENSURE_OR_GO_EXIT(pApdu != NULL);

    pApdu->rxlen = 0;
    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    // remote JC Terminal header construction
    txLen = pApdu->buflen;
    memcpy(pCmd, Header, sizeof(Header));
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = txLen & 0xFF;
    memcpy(&pCmd[4], pApdu->pBuf, pApdu->buflen);

    ENSURE_OR_GO_EXIT(pApdu->buflen <= UINT16_MAX - 4);
    pApdu->buflen += 4; /* header & length */

    LOG_MAU8_D("H>", pCmd, 4);
    LOG_MAU8_D("Tx>", pCmd + 4, pApdu->buflen - 4);
    status = WriteFile(pComHandle, pCmd, pApdu->buflen, &WrittenLen, NULL);
    if ((status == 0) || (WrittenLen != pApdu->buflen)) {
        if (fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen) < 0) {
            LOG_E("Error in logging error to stderr");
        }
        goto exit;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        DWORD numBytesRead = 0;
        status =
            ReadFile(pComHandle, (char *)&pRsp[totalReceived], (MAX_BUF_SIZE - totalReceived), &numBytesRead, NULL);
        ENSURE_OR_GO_EXIT(numBytesRead <= INT32_MAX);

        if (status == 0) {
            if ((fprintf(stderr, "Client: recv() failed: error %i.\n", numBytesRead)) < 0) {
                LOG_E("Error in logging error to stderr");
            }
            rv = SMCOM_RCV_FAILED;
            goto exit;
        }
        else {
            totalReceived += numBytesRead;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            if (expectedLength > (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3])))) {
                rv = SMCOM_RCV_FAILED;
                goto exit;
            }
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

    totalReceived -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    ENSURE_OR_GO_EXIT(totalReceived <= pApdu->rxlen);
    memcpy(pApdu->pBuf, &pRsp[4], totalReceived);
    LOG_MAU8_D("<H", pRsp, 4);
    LOG_MAU8_D("<Rx", pApdu->pBuf, totalReceived);

    pApdu->rxlen = (U16)totalReceived;
    // reset offset for subsequent response parsing
    pApdu->offset = 0;
    rv            = SMCOM_OK;
exit:
    return rv;
}

U32 smComVCom_TransceiveRaw(void *conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    DWORD numBytesRead = 0;
    U32 answerReceived = 0;
    U32 len            = 0;
    U8 status          = 0;
    DWORD WrittenLen   = 0;
#if defined(LOG_SOCK) || defined(DBG_LOG_SOCK)
    int i = 0;
#endif
    U32 readOffset    = 0;
    U8 headerParsed   = 0;
    U8 correctHeader  = 0;
    U32 rv            = SMCOM_COM_FAILED;
    HANDLE pComHandle = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;

    ENSURE_OR_GO_EXIT(pTx != NULL);
    ENSURE_OR_GO_EXIT(pRx != NULL);
    ENSURE_OR_GO_EXIT(pRxLen != NULL);

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);

    ENSURE_OR_GO_EXIT(txLen <= UINT16_MAX - 4);

    memcpy(&pCmd[4], pTx, txLen);
    txLen += 4; /* header + len */

    LOG_MAU8_D("H>", pCmd, 4);
    LOG_MAU8_D("Tx>", pCmd + 4, txLen - 4);
    status = WriteFile(pComHandle, pCmd, txLen, &WrittenLen, NULL);
    if ((status == false) || (WrittenLen != txLen)) {
        if (fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen) < 0) {
            LOG_E("Error in logging error to stderr");
        }
        return SMCOM_SND_FAILED;
    }
    else {
    }

    numBytesRead = REMOTE_JC_SHELL_HEADER_LEN; // receive at least the JCTerminal header

    while ((numBytesRead > 0) || (answerReceived == 0)) {
        status = ReadFile(pComHandle, (char *)pRsp, MAX_BUF_SIZE, &numBytesRead, NULL);

        if (status == 0) {
            return SMCOM_RCV_FAILED;
        }
        else // data received
        {
            if (numBytesRead > 4) {
                LOG_MAU8_D("<H", pRsp, 4);
                LOG_MAU8_D("<Rx", pRsp + 4, numBytesRead - 4);
            }
            while (numBytesRead > 0) // parse all bytes
            {
                if (headerParsed == 1) // header already parsed; get data
                {
                    ENSURE_OR_GO_EXIT(len <= INT32_MAX);
                    if (numBytesRead >= (S32)len) {
                        if (correctHeader == 1) {
                            ENSURE_OR_GO_EXIT(len <= *pRxLen);
                            ENSURE_OR_GO_EXIT(len <= (MAX_BUF_SIZE - readOffset));
                            memcpy(&pRx[0], &pRsp[readOffset], len);
                            answerReceived = 1;
                        }
                        else {
                            // reset header parsed
                            readOffset += len;
                            headerParsed = 0;
                        }
                        numBytesRead -= len;

                        if (numBytesRead == 0) // no data left, reset readOffset
                        {
                            readOffset = 0;
                        }
                    }
                    else {
                        // data too small according header => Error
                        if ((fprintf(stderr, "Failed reading data %x %x\n", numBytesRead, len)) < 0) {
                            LOG_E("Error in logging error to stderr!");
                        }
                        return SMCOM_RCV_FAILED;
                    }
                }
                else // parse header
                {
                    ENSURE_OR_GO_EXIT(readOffset <= MAX_BUF_SIZE - 3);
                    len = ((pRsp[readOffset + 2] << 8) | (pRsp[readOffset + 3]));

                    if (pRsp[readOffset] == REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA) {
                        // type correct => copy the data
                        numBytesRead -= REMOTE_JC_SHELL_HEADER_LEN;
                        if (numBytesRead > 0) // data left to read
                        {
                            readOffset += REMOTE_JC_SHELL_HEADER_LEN;
                        }
                        correctHeader = 1;
                    }
                    else {
                        // type incorrect => skip the data as well and try again if data are left
                        readOffset += REMOTE_JC_SHELL_HEADER_LEN;
                        numBytesRead -= REMOTE_JC_SHELL_HEADER_LEN;
                        correctHeader = 0;
                    }
                    headerParsed = 1;
                }
            }
        }
    }

    *pRxLen = len;

    rv = SMCOM_OK;
exit:
    return rv;
}

U32 smComVCom_Close(void *conn_ctx)
{
    U16 fRetVal        = 0;
    U16 status         = 1;
    U32 u32status      = 0;
    U8 Cmd[4]          = {MTY_CLOSE, NAD, 0, 0};
    DWORD WrittenLen   = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    U32 expectedLength = 0;
    HANDLE pComHandle  = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;

    fRetVal = WriteFile(pComHandle, Cmd, sizeof(Cmd), &WrittenLen, NULL);
    if ((fRetVal == 0) || (WrittenLen != sizeof(Cmd))) {
        goto exit;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength  = 0;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        if (maxCommLength > (MAX_BUF_SIZE - totalReceived)) {
            goto exit;
        }
        fRetVal = ReadFile(pComHandle, (char *)&pRsp[totalReceived], maxCommLength, &numBytesRead, NULL);
        if (numBytesRead > INT32_MAX) {
            goto exit;
        }
        if (fRetVal == 0) {
            if (fprintf(stderr, "Client: recv() failed: error %i.\n", numBytesRead) < 0) {
                LOG_D("Error in logging error to stderr!");
            }
            goto exit;
        }
        else {
            totalReceived += numBytesRead;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            if (expectedLength > (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3])))) {
                goto exit;
            }
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }
    fRetVal     = CloseHandle(pComHandle);
    pComHandle  = INVALID_HANDLE_VALUE;
    gpComHandle = INVALID_HANDLE_VALUE;
    u32status   = GetLastError();
    if (u32status == ERROR_SUCCESS) {
        status = SMCOM_OK;
    }
    else {
        LOG_D("GetLastError returned");
        LOG_U32_D(u32status);
        status = (U16)u32status;
    }
exit:
    return status;
}

U32 smComVCom_GPIOInit(void *conn_ctx, U8 gpioPIN, U8 setInOutDir)
{
    U16 status = 0;
    U8 Cmd[4]  = {MTY_GPIO_PIN_INIT, NAD, 0, 0};

    DWORD WrittenLen   = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    U32 expectedLength = 0;
    uint16_t txLen     = sizeof(gpioPIN) + sizeof(setInOutDir);

    memcpy(pCmd, Cmd, 2);
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    pCmd[5] = setInOutDir;
    txLen += 4; /* header + len */
    LOG_MAU8_D("H>", pCmd, 4);
    LOG_MAU8_D("Tx>", pCmd + 4, txLen - 4);
    HANDLE pComHandle = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;

    status = (WriteFile(pComHandle, pCmd, txLen, &WrittenLen, NULL) != 0) ? true : false;
    if ((status == false) || (WrittenLen != txLen)) {
        if (fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen) < 0) {
            LOG_E("Error in logging error to stderr");
        }
        goto exit;
    }
    else {
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength  = 0;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        if (maxCommLength > (MAX_BUF_SIZE - totalReceived)) {
            status = 0;
            goto exit;
        }
        status = (ReadFile(pComHandle, (char *)&pRsp[totalReceived], maxCommLength, &numBytesRead, NULL) != 0) ? true :
                                                                                                                 false;
        if (numBytesRead > INT32_MAX) {
            status = 0;
            goto exit;
        }
        if (status == 0) {
            if (fprintf(stderr, "Client: recv() failed: error %i.\n", numBytesRead) < 0) {
                LOG_D("Error in logging error to stderr!");
            }
            goto exit;
        }
        else {
            totalReceived += numBytesRead;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            if (expectedLength > (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3])))) {
                goto exit;
            }
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

    if ((pRsp[0] != MTY_GPIO_PIN_INIT) || (totalReceived != REMOTE_JC_SHELL_HEADER_LEN)) {
        status = 0;
        goto exit;
    }

    LOG_MAU8_D("<H", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
    LOG_MAU8_D("<Rx", pRsp + REMOTE_JC_SHELL_HEADER_LEN, totalReceived - REMOTE_JC_SHELL_HEADER_LEN);

exit:
    return status;
}

U32 smComVCom_GPIOSet(void *conn_ctx, U8 gpioPIN)
{
    U16 status = 0;
    U8 Cmd[4]  = {MTY_GPIO_PORT_SET, NAD, 0, 0};

    DWORD WrittenLen   = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    U32 expectedLength = 0;
    uint16_t txLen     = sizeof(gpioPIN);

    memcpy(pCmd, Cmd, 2);
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    txLen += 4; /* header + len */
    LOG_MAU8_D("H>", pCmd, 4);
    LOG_MAU8_D("Tx>", pCmd + 4, txLen - 4);
    HANDLE pComHandle = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;

    status = WriteFile(pComHandle, pCmd, txLen, &WrittenLen, NULL);
    if ((status == false) || (WrittenLen != txLen)) {
        if (fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen) < 0) {
            LOG_E("Error in logging error to stderr");
        }
        goto exit;
    }
    else {
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength  = 0;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        if (maxCommLength > (MAX_BUF_SIZE - totalReceived)) {
            status = 0;
            goto exit;
        }
        status = (ReadFile(pComHandle, (char *)&pRsp[totalReceived], maxCommLength, &numBytesRead, NULL) != 0) ? true :
                                                                                                                 false;
        if (numBytesRead > INT32_MAX) {
            goto exit;
        }
        if (status == 0) {
            if (fprintf(stderr, "Client: recv() failed: error %i.\n", numBytesRead) < 0) {
                LOG_D("Error in logging error to stderr");
            }
            goto exit;
        }
        else {
            totalReceived += numBytesRead;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            if (expectedLength > (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3])))) {
                status = 0;
                goto exit;
            }
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

    if ((pRsp[0] != MTY_GPIO_PORT_SET) || (totalReceived != REMOTE_JC_SHELL_HEADER_LEN)) {
        goto exit;
    }
    LOG_MAU8_D("<H", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
    LOG_MAU8_D("<Rx", pRsp + REMOTE_JC_SHELL_HEADER_LEN, totalReceived - REMOTE_JC_SHELL_HEADER_LEN);

exit:
    return status;
}

U32 smComVCom_GPIOClear(void *conn_ctx, U8 gpioPIN)
{
    U16 status = 0;
    U8 Cmd[4]  = {MTY_GPIO_PORT_CLEAR, NAD, 0, 0};

    DWORD WrittenLen   = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    U32 expectedLength = 0;
    uint16_t txLen     = sizeof(gpioPIN);

    memcpy(pCmd, Cmd, 2);
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    txLen += 4; /* header + len */

    LOG_MAU8_D("H>", pCmd, 4);
    LOG_MAU8_D("Tx>", pCmd + 4, txLen - 4);
    HANDLE pComHandle = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;

    status = (WriteFile(pComHandle, pCmd, txLen, &WrittenLen, NULL) != 0) ? true : false;
    if ((status == false) || (WrittenLen != txLen)) {
        if (fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen) < 0) {
            LOG_D("Error in logging error to stderr!");
        }
        goto exit;
    }
    else {
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength  = 0;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        if (maxCommLength > (MAX_BUF_SIZE - totalReceived)) {
            goto exit;
        }
        status = (ReadFile(pComHandle, (char *)&pRsp[totalReceived], maxCommLength, &numBytesRead, NULL) != 0) ? true :
                                                                                                                 false;
        if (numBytesRead > INT32_MAX) {
            goto exit;
        }
        if (status == 0) {
            if (fprintf(stderr, "Client: recv() failed: error %i.\n", numBytesRead) < 0) {
                LOG_D("Error in logging error to stderr!");
            }
            goto exit;
        }
        else {
            totalReceived += numBytesRead;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            if (expectedLength > (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3])))) {
                goto exit;
            }
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

    if ((pRsp[0] != MTY_GPIO_PORT_CLEAR) || (totalReceived != REMOTE_JC_SHELL_HEADER_LEN)) {
        status = 0;
        goto exit;
    }
    LOG_MAU8_D("<H", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
    LOG_MAU8_D("<Rx", pRsp + REMOTE_JC_SHELL_HEADER_LEN, totalReceived - REMOTE_JC_SHELL_HEADER_LEN);

exit:
    return status;
}

U32 smComVCom_GPIOToggle(void *conn_ctx, U8 gpioPIN)
{
    U16 status = 0;
    U8 Cmd[4]  = {MTY_GPIO_PORT_TOGGLE, NAD, 0, 0};

    DWORD WrittenLen   = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    U32 expectedLength = 0;
    uint16_t txLen     = sizeof(gpioPIN);

    memcpy(pCmd, Cmd, 2);
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    txLen += 4; /* header + len */

    LOG_MAU8_D("H>", pCmd, 4);
    LOG_MAU8_D("Tx>", pCmd + 4, txLen - 4);
    HANDLE pComHandle = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;
    status            = WriteFile(pComHandle, pCmd, txLen, &WrittenLen, NULL);
    if ((status == false) || (WrittenLen != txLen)) {
        if (fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen) < 0) {
            LOG_E("Error in logging error to stderr");
        }
        goto exit;
    }
    else {
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength  = 0;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        if (maxCommLength > (MAX_BUF_SIZE - totalReceived)) {
            status = 0;
            goto exit;
        }
        status = (ReadFile(pComHandle, (char *)&pRsp[totalReceived], maxCommLength, &numBytesRead, NULL) != 0) ? true :
                                                                                                                 false;
        if (numBytesRead > INT32_MAX) {
            goto exit;
        }
        if (status == 0) {
            if (fprintf(stderr, "Client: recv() failed: error %i.\n", numBytesRead) < 0) {
                LOG_D("Error in logging error to stderr!");
            }
            goto exit;
        }
        else {
            totalReceived += numBytesRead;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            if (expectedLength > (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3])))) {
                status = 0;
                goto exit;
            }
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

    if ((pRsp[0] != MTY_GPIO_PORT_TOGGLE) || (totalReceived != REMOTE_JC_SHELL_HEADER_LEN)) {
        goto exit;
    }
    LOG_MAU8_D("<H", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
    LOG_MAU8_D("<Rx", pRsp + REMOTE_JC_SHELL_HEADER_LEN, totalReceived - REMOTE_JC_SHELL_HEADER_LEN);

exit:
    return status;
}

U32 smComVCom_GPIORead(void *conn_ctx, U8 gpioPIN, U8 *pRx, U32 *pRxLen)
{
    U16 status = 0;
    U8 Cmd[4]  = {MTY_GPIO_PIN_READ, NAD, 0, 0};

    ENSURE_OR_GO_EXIT(NULL != pRx)
    ENSURE_OR_GO_EXIT(NULL != pRxLen)

    memcpy(pCmd, Cmd, 2);
    pCmd[4]        = gpioPIN;
    uint16_t txLen = sizeof(gpioPIN);
    pCmd[2]        = (txLen & 0xFF00) >> 8;
    pCmd[3]        = txLen & 0xFF;
    txLen += 4;
    DWORD WrittenLen   = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    U32 expectedLength = 0;

    LOG_MAU8_D("H>", pCmd, 4);
    LOG_MAU8_D("Tx>", pCmd + 4, txLen - 4);
    HANDLE pComHandle = (conn_ctx == NULL) ? gpComHandle : (HANDLE)conn_ctx;
    status            = WriteFile(pComHandle, pCmd, txLen, &WrittenLen, NULL);
    if ((status == false) || (WrittenLen != txLen)) {
        if (fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen) < 0) {
            LOG_D("Error in logging error to stderr");
        }
        goto exit;
    }
    else {
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength  = 0;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        if (maxCommLength > (MAX_BUF_SIZE - totalReceived)) {
            goto exit;
        }
        status = (ReadFile(pComHandle, (char *)&pRsp[totalReceived], maxCommLength, &numBytesRead, NULL) != 0) ? true :
                                                                                                                 false;
        if (numBytesRead > INT32_MAX) {
            goto exit;
        }
        if (status == 0) {
            if (fprintf(stderr, "Client: recv() failed: error %i.\n", numBytesRead) < 0) {
                LOG_D("Error in logging error to stderr!");
            }
            goto exit;
        }
        else {
            totalReceived += numBytesRead;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            if (expectedLength > (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3])))) {
                goto exit;
            }
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

    if (pRsp[0] != MTY_GPIO_PIN_READ) {
        goto exit;
    }
    if (totalReceived < REMOTE_JC_SHELL_HEADER_LEN) {
        LOG_E("Received response is missing the header itself!");
        goto exit;
    }

    LOG_MAU8_D("<H", pRsp, 4);
    LOG_MAU8_D("<Rx", pRsp + 4, totalReceived - 4);

    memcpy(&pRx[0], &pRsp[REMOTE_JC_SHELL_HEADER_LEN], totalReceived - REMOTE_JC_SHELL_HEADER_LEN);
    *pRxLen = totalReceived - REMOTE_JC_SHELL_HEADER_LEN;

exit:
    return status;
}