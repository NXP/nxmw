/**
 * @file smComSocket_linux.c
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2016, 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * @par Description
 *
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>
#include <netdb.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include "smCom.h"
#include "smComSocket.h"
#include "sm_types.h"
#include "nxEnsure.h"
#include "sm_timer.h"
#include "nxLog_msg.h"

// Enable define of CHECK_ON_CIP to enable check on returned ATR (don't enable this when using the Smart Card Server ...)
#define CHECK_ON_CIP

#define REMOTE_JC_SHELL_HEADER_LEN (4)
#define REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA (0x01)

#include "sm_apdu.h"
#include "smComSocket_fd.h"

#define MAX_BUF_SIZE (MAX_APDU_BUF_LENGTH)

#define MTY_GPIO_PIN_INIT 0x04
#define MTY_GPIO_PORT_SET 0x05
#define MTY_GPIO_PORT_CLEAR 0x06
#define MTY_GPIO_PORT_TOGGLE 0x07
#define MTY_GPIO_PIN_READ 0x08

static U8 Header[2] = {0x01, 0x00};
static U8 sockapdu[MAX_BUF_SIZE];
static U8 response[MAX_BUF_SIZE];

static U8 *pCmd = (U8 *)&sockapdu;
static U8 *pRsp = (U8 *)&response;

#if defined(__OSX_AVAILABLE) || defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
#define READ_RECV(FD, PTR, BUFLEN) read((FD), (PTR), (BUFLEN))
#define READ_RECV_STR "read"
#define WRITE_SEND(FD, PTR, BUFLEN) write((FD), (PTR), (BUFLEN))
#define WRITE_SEND_STR "write"
#else
#define READ_RECV(FD, PTR, BUFLEN) recv((FD), (PTR), (BUFLEN), 0)
#define READ_RECV_STR "recv"
#define WRITE_SEND(FD, PTR, BUFLEN) send((FD), (PTR), (BUFLEN), 0)
#define WRITE_SEND_STR "send"
#endif

U32 smComSocket_CloseFD(int fd)
{
    long int readWriteLen = 0;
    U8 Cmd[4]             = {MTY_CLOSE, MYT_DEFAULT_NAD, 0, 0};
    U32 totalReceived     = 0;
    U8 lengthReceived     = 0;
    U32 expectedLength    = 0;
    U8 retval             = 1;

    LOG_D("Closing()");

    readWriteLen = WRITE_SEND(fd, Cmd, sizeof(Cmd));
    if (readWriteLen < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", readWriteLen);
        return SMCOM_SND_FAILED;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        if (maxCommLength > MAX_BUF_SIZE - totalReceived) {
            close(fd);
            return SMCOM_RCV_FAILED;
        }
        readWriteLen = READ_RECV(fd, (char *)&pRsp[totalReceived], maxCommLength);

        if (readWriteLen <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", readWriteLen);
            close(fd);
            return SMCOM_RCV_FAILED;
        }
        else {
            totalReceived += readWriteLen;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

    close(fd);
    retval = 0;

exit:
    return retval;
}

U32 smComSocket_GetCIPFD(int fd, U8 *pCip, U16 *cipLen)
{
    U8 retval             = 0;
    long int readWriteLen = 0;

    U32 expectedLength = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;

    // wait 256 ms
    U8 cipCmd[8] = {MTY_WAIT_FOR_CARD, MYT_DEFAULT_NAD, 0, 4, 0, 0, 1, 0};

    ENSURE_OR_GO_EXIT(pCip != NULL);
    ENSURE_OR_GO_EXIT(cipLen != NULL);

    LOG_MAU8_D("cipCmd", cipCmd, sizeof(cipCmd));

    readWriteLen = WRITE_SEND(fd, (const char *)cipCmd, sizeof(cipCmd));

    if (readWriteLen < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", readWriteLen);
        retval = 1;
        goto exit;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        LOG_D("Enter: " READ_RECV_STR "() ");
        ENSURE_OR_GO_EXIT(expectedLength <= MAX_BUF_SIZE - totalReceived);
        readWriteLen = READ_RECV(fd, (char *)&pRsp[totalReceived], expectedLength);
        LOG_D("Exit: " READ_RECV_STR "(). readWriteLen=%d", readWriteLen);

        if (readWriteLen <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", readWriteLen);
            close(fd);
            retval = 0;
            ENSURE_OR_GO_EXIT(0);
        }
        else {
            totalReceived += readWriteLen;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }
    readWriteLen = totalReceived;

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Rsp:Hdr", pRsp, 4);
#endif

    readWriteLen -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    ENSURE_OR_GO_EXIT(readWriteLen <= *cipLen);
    ENSURE_OR_GO_EXIT(readWriteLen <= MAX_BUF_SIZE - 4);
    memcpy(pCip, pRsp + 4, readWriteLen);

    LOG_MAU8_D("Cip", pCip, readWriteLen);

    *cipLen = (U16)readWriteLen;
exit:
    return retval;
}

U32 smComSocket_TransceiveFD(int fd, apdu_t *pApdu)
{
    long int retval;

    U32 txLen          = 0;
    U32 expectedLength = 0;
    U32 totalReceived  = 0;
    U8 lengthReceived  = 0;
    U32 rv             = SMCOM_SND_FAILED;

    ENSURE_OR_GO_EXIT(pApdu != NULL);

    pApdu->rxlen = 0;
    // TODO (?): adjustments on Le and Lc for SCP still to be done
    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    // remote JC Terminal header construction
    txLen = pApdu->buflen;
    memcpy(pCmd, Header, sizeof(Header));
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = txLen & 0xFF;

    ENSURE_OR_GO_EXIT(pApdu->buflen <= MAX_BUF_SIZE - 4);
    memcpy(&pCmd[4], pApdu->pBuf, pApdu->buflen);
    pApdu->buflen += 4; /* header & length */

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Cmd:Hdr", pCmd, 4);
#endif

    LOG_MAU8_D("Cmd", pCmd + 4, pApdu->buflen - 4);

    retval = WRITE_SEND(fd, (const char *)pCmd, pApdu->buflen);
    if (retval < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", retval);
        return SMCOM_SND_FAILED;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        retval = READ_RECV(fd, (char *)&pRsp[totalReceived], (MAX_BUF_SIZE - totalReceived));

        if (retval <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", retval);
            close(fd);
            rv = SMCOM_RCV_FAILED;
            ENSURE_OR_GO_EXIT(0);
        }
        else {
            totalReceived += retval;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }
    retval = totalReceived;

    retval -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    ENSURE_OR_GO_EXIT(retval <= pApdu->rxlen);
    ENSURE_OR_GO_EXIT(retval <= MAX_BUF_SIZE - 4);
    memcpy(pApdu->pBuf, &pRsp[4], retval);

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Rsp:Hdr", pRsp, 4);
#endif
    LOG_MAU8_D("Rsp", pApdu->pBuf, retval);

    pApdu->rxlen = (U16)retval;
    // reset offset for subsequent response parsing
    pApdu->offset = 0;
    rv            = SMCOM_OK;
exit:
    return rv;
}

U32 smComSocket_TransceiveRawFD(int fd, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    long int readWriteLen = 0;
    U32 expectedLength    = 0;
    int lengthReceived    = 0;

    U32 totalReceived = 0;
    U32 rv            = SMCOM_COM_FAILED;

    ENSURE_OR_GO_EXIT(pTx != NULL);
    ENSURE_OR_GO_EXIT(pRx != NULL);
    ENSURE_OR_GO_EXIT(pRxLen != NULL);

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    ENSURE_OR_GO_EXIT(txLen <= MAX_BUF_SIZE - 4);
    memcpy(&pCmd[4], pTx, txLen);
    txLen += 4; /* header + len */

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Cmd:Hdr", pCmd, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    LOG_MAU8_D("Cmd", pCmd + REMOTE_JC_SHELL_HEADER_LEN, txLen - REMOTE_JC_SHELL_HEADER_LEN);

    readWriteLen = WRITE_SEND(fd, (const char *)pCmd, txLen);
    if (readWriteLen < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", readWriteLen);
        return SMCOM_SND_FAILED;
    }
    else {
#ifdef DBG_LOG_SOCK
        LOG_D("Client: " WRITE_SEND_STR "() is OK.\r\n");
#endif
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        readWriteLen = READ_RECV(fd, (char *)&pRsp[totalReceived], MAX_BUF_SIZE - totalReceived);

        if (readWriteLen <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", readWriteLen);
            close(fd);
            rv = SMCOM_RCV_FAILED;
            ENSURE_OR_GO_EXIT(0);
        }
        else {
            totalReceived += readWriteLen;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Rsp:Hdr", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    ENSURE_OR_GO_EXIT((totalReceived - REMOTE_JC_SHELL_HEADER_LEN) <= *pRxLen);
    ENSURE_OR_GO_EXIT((totalReceived - REMOTE_JC_SHELL_HEADER_LEN) <= (MAX_BUF_SIZE - REMOTE_JC_SHELL_HEADER_LEN));
    memcpy(pRx, &pRsp[REMOTE_JC_SHELL_HEADER_LEN], totalReceived - REMOTE_JC_SHELL_HEADER_LEN);
    *pRxLen = totalReceived - REMOTE_JC_SHELL_HEADER_LEN;

    LOG_MAU8_D("Rsp", pRx, *pRxLen);

    rv = SMCOM_OK;
exit:
    return rv;
}

U32 smComSocket_LockChannelFD(int fd)
{
    long int readWriteLen = 0;
    U8 retval             = 0;
    U32 expectedLength    = 0;
    U32 totalReceived     = 0;

    // wait 256 ms
    U8 LockCmd[4] = {MTY_LOCK, 0, 0, 0};
    U8 LockRsp[4] = {
        0,
    };

    readWriteLen = WRITE_SEND(fd, (const char *)LockCmd, sizeof(LockCmd));
    if (readWriteLen < 0) {
        if (0 < fprintf(stderr, "Client: send() failed: error %li.\n", readWriteLen)) {
            LOG_W("Client: fprintf() failed");
        }
        retval = 0;
        goto exit;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength;
        maxCommLength = expectedLength - totalReceived;

        ENSURE_OR_GO_EXIT(maxCommLength <= sizeof(LockRsp) - totalReceived);
        readWriteLen = READ_RECV(fd, (char *)&LockRsp[totalReceived], maxCommLength);
        if (readWriteLen <= 0) {
            if (0 < fprintf(stderr, "Client: recv() failed: error %li.\n", readWriteLen)) {
                LOG_W("Client: fprintf() failed");
            }
            close(fd);
            retval = 0;
            goto exit;
        }
        else {
            totalReceived += readWriteLen;
        }
    }
    retval = LockRsp[3];

exit:
    return retval;
}

U32 smComSocket_UnlockChannelFD(int fd)
{
    long int readWriteLen = 0;
    U8 retval             = 0;
    U32 expectedLength    = 0;
    U32 totalReceived     = 0;

    // wait 256 ms
    U8 UnlockCmd[4] = {MTY_UNLOCK, 0, 0, 0};
    U8 UnlockRsp[4] = {
        0,
    };

    readWriteLen = WRITE_SEND(fd, (const char *)UnlockCmd, sizeof(UnlockCmd));
    if (readWriteLen < 0) {
        if (0 < fprintf(stderr, "Client: send() failed: error %li.\n", readWriteLen)) {
            LOG_W("Client: fprintf() failed");
        }
        retval = 0;
        goto exit;
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength;
        maxCommLength = expectedLength - totalReceived;

        ENSURE_OR_GO_EXIT(maxCommLength <= sizeof(UnlockRsp) - totalReceived);
        readWriteLen = READ_RECV(fd, (char *)&UnlockRsp[totalReceived], maxCommLength);
        if (readWriteLen <= 0) {
            if (0 < fprintf(stderr, "Client: recv() failed: error %li.\n", readWriteLen)) {
                LOG_W("Client: fprintf() failed");
            }
            close(fd);
            retval = 0;
            goto exit;
        }
        else {
            totalReceived += readWriteLen;
        }
    }
    retval = UnlockRsp[3];

exit:
    return retval;
}

U32 smComSocket_GPIOInitFD(int fd, U8 gpioPIN, U8 setInOutDir)
{
    long int readWriteLen = 0;
    U32 expectedLength    = 0;
    int lengthReceived    = 0;

    U32 totalReceived = 0;
    U32 rv            = false;
    uint16_t txLen    = sizeof(gpioPIN) + sizeof(setInOutDir);

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[0] = MTY_GPIO_PIN_INIT;
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    pCmd[5] = setInOutDir;
    txLen += 4; /* header + len */

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Cmd:Hdr", pCmd, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    LOG_MAU8_D("Cmd", pCmd + REMOTE_JC_SHELL_HEADER_LEN, txLen - REMOTE_JC_SHELL_HEADER_LEN);

    readWriteLen = WRITE_SEND(fd, (const char *)pCmd, txLen);
    if (readWriteLen < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", readWriteLen);
        rv = false;
        goto exit;
    }
    else {
#ifdef DBG_LOG_SOCK
        LOG_D("Client: " WRITE_SEND_STR "() is OK.\r\n");
#endif
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        readWriteLen = READ_RECV(fd, (char *)&pRsp[totalReceived], MAX_BUF_SIZE);

        if (readWriteLen <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", readWriteLen);
            close(fd);
            rv = false;
            goto exit;
        }
        else {
            totalReceived += readWriteLen;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Rsp:Hdr", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    if ((pRsp[0] != MTY_GPIO_PIN_INIT) || (readWriteLen != REMOTE_JC_SHELL_HEADER_LEN)) {
        return false;
    }

    rv = true;

exit:
    return rv;
}

U32 smComSocket_GPIOSetFD(int fd, U8 gpioPIN)
{
    long int readWriteLen = 0;
    U32 expectedLength    = 0;
    int lengthReceived    = 0;

    U32 totalReceived = 0;
    U32 rv            = false;
    uint16_t txLen    = sizeof(gpioPIN);

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[0] = MTY_GPIO_PORT_SET;
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    txLen += 4; /* header + len */

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Cmd:Hdr", pCmd, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    LOG_MAU8_D("Cmd", pCmd + REMOTE_JC_SHELL_HEADER_LEN, txLen - REMOTE_JC_SHELL_HEADER_LEN);

    readWriteLen = WRITE_SEND(fd, (const char *)pCmd, txLen);
    if (readWriteLen < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", readWriteLen);
        rv = false;
        goto exit;
    }
    else {
#ifdef DBG_LOG_SOCK
        LOG_D("Client: " WRITE_SEND_STR "() is OK.\r\n");
#endif
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        readWriteLen = READ_RECV(fd, (char *)&pRsp[totalReceived], MAX_BUF_SIZE);

        if (readWriteLen <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", readWriteLen);
            close(fd);
            rv = false;
            goto exit;
        }
        else {
            totalReceived += readWriteLen;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Rsp:Hdr", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    if ((pRsp[0] != MTY_GPIO_PORT_SET) || (readWriteLen != REMOTE_JC_SHELL_HEADER_LEN)) {
        return false;
    }

    rv = true;
exit:
    return rv;
}

U32 smComSocket_GPIOClearFD(int fd, U8 gpioPIN)
{
    long int readWriteLen = 0;
    U32 expectedLength    = 0;
    int lengthReceived    = 0;

    U32 totalReceived = 0;
    U32 rv            = false;
    uint16_t txLen    = sizeof(gpioPIN);

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[0] = MTY_GPIO_PORT_CLEAR;
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    txLen += 4; /* header + len */

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Cmd:Hdr", pCmd, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    LOG_MAU8_D("Cmd", pCmd + REMOTE_JC_SHELL_HEADER_LEN, txLen - REMOTE_JC_SHELL_HEADER_LEN);

    readWriteLen = WRITE_SEND(fd, (const char *)pCmd, txLen);
    if (readWriteLen < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", readWriteLen);
        rv = false;
        goto exit;
    }
    else {
#ifdef DBG_LOG_SOCK
        LOG_D("Client: " WRITE_SEND_STR "() is OK.\r\n");
#endif
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        readWriteLen = READ_RECV(fd, (char *)&pRsp[totalReceived], MAX_BUF_SIZE);

        if (readWriteLen <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", readWriteLen);
            close(fd);
            rv = false;
            goto exit;
        }
        else {
            totalReceived += readWriteLen;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Rsp:Hdr", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    if ((pRsp[0] != MTY_GPIO_PORT_CLEAR) || (readWriteLen != REMOTE_JC_SHELL_HEADER_LEN)) {
        return false;
    }

    rv = true;

exit:
    return rv;
}

U32 smComSocket_GPIOToggleFD(int fd, U8 gpioPIN)
{
    long int readWriteLen = 0;
    U32 expectedLength    = 0;
    int lengthReceived    = 0;

    U32 totalReceived = 0;
    U32 rv            = false;
    uint16_t txLen    = sizeof(gpioPIN);

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[0] = MTY_GPIO_PORT_TOGGLE;
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    txLen += 4; /* header + len */

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Cmd:Hdr", pCmd, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    LOG_MAU8_D("Cmd", pCmd + REMOTE_JC_SHELL_HEADER_LEN, txLen - REMOTE_JC_SHELL_HEADER_LEN);

    readWriteLen = WRITE_SEND(fd, (const char *)pCmd, txLen);
    if (readWriteLen < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", readWriteLen);
        rv = false;
        goto exit;
    }
    else {
#ifdef DBG_LOG_SOCK
        LOG_D("Client: " WRITE_SEND_STR "() is OK.\r\n");
#endif
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        readWriteLen = READ_RECV(fd, (char *)&pRsp[totalReceived], MAX_BUF_SIZE);

        if (readWriteLen <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", readWriteLen);
            close(fd);
            rv = false;
            goto exit;
        }
        else {
            totalReceived += readWriteLen;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Rsp:Hdr", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    if ((pRsp[0] != MTY_GPIO_PORT_TOGGLE) || (readWriteLen != REMOTE_JC_SHELL_HEADER_LEN)) {
        return false;
    }

    rv = true;

exit:
    return rv;
}

U32 smComSocket_GPIOReadFD(int fd, U8 gpioPIN, U8 *pRx, U32 *pRxLen)
{
    long int readWriteLen = 0;
    U32 expectedLength    = 0;
    int lengthReceived    = 0;

    U32 totalReceived = 0;
    U32 rv            = false;
    uint16_t txLen    = sizeof(gpioPIN);

    ENSURE_OR_GO_EXIT(pRx != NULL);
    ENSURE_OR_GO_EXIT(pRxLen != NULL);

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[0] = MTY_GPIO_PIN_READ;
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    pCmd[4] = gpioPIN;
    txLen += 4; /* header + len */

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Cmd:Hdr", pCmd, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    LOG_MAU8_D("Cmd", pCmd + REMOTE_JC_SHELL_HEADER_LEN, txLen - REMOTE_JC_SHELL_HEADER_LEN);

    readWriteLen = WRITE_SEND(fd, (const char *)pCmd, txLen);
    if (readWriteLen < 0) {
        LOG_W("Client: " WRITE_SEND_STR "() failed: error %li", readWriteLen);
        rv = false;
        goto exit;
    }
    else {
#ifdef DBG_LOG_SOCK
        LOG_D("Client: " WRITE_SEND_STR "() is OK.\r\n");
#endif
    }

    expectedLength = REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        readWriteLen = READ_RECV(fd, (char *)&pRsp[totalReceived], MAX_BUF_SIZE);

        if (readWriteLen <= 0) {
            LOG_W("Client: " READ_RECV_STR "() failed: error %li", readWriteLen);
            close(fd);
            rv = false;
            goto exit;
        }
        else {
            totalReceived += readWriteLen;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) && (lengthReceived == 0)) {
            ENSURE_OR_GO_EXIT(expectedLength <= (UINT32_MAX - ((pRsp[2] << 8) | (pRsp[3]))));
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }

#ifdef LOG_FULL_CMD_RSP
    LOG_MAU8_D("Rsp:Hdr", pRsp, REMOTE_JC_SHELL_HEADER_LEN);
#endif

    memcpy(pRx, &pRsp[REMOTE_JC_SHELL_HEADER_LEN], totalReceived - REMOTE_JC_SHELL_HEADER_LEN);
    *pRxLen = totalReceived - REMOTE_JC_SHELL_HEADER_LEN;

    LOG_MAU8_D("Rsp", pRx, *pRxLen);

    rv = true;
exit:
    return rv;
}
