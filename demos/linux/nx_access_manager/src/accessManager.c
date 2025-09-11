/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h> // memset
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>

#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "smCom.h"
#include "fsl_sss_nx_apis.h"
#include <fsl_sss_nx_auth.h>

#if defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC)
#include "smComPCSC.h"
#endif
#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
#include "smComT1oI2C.h"
#endif

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "sm_apdu.h"
#include "accessManager.h"
#include "accessManager_com.h"

#define BACKLOG 5 // how many pending connections queue will hold
#define ACCESS_MGR_VERSION_MAJOR 1
#define ACCESS_MGR_VERSION_MINOR 1

typedef struct client_struct
{
    int sock;
    /* place additional client attributes here */
    int nLock;
    struct client_struct *next;
} client_t;

#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
extern const char gszCOMPortDefault[];
#endif

client_t *addClient(client_t *head, int sock);
client_t *amRemoveObsoleteClients(client_t *head, int *fOnHold);
client_t *amDeleteAllClients(client_t *head);

int main(int argc, char **argv)
{
    int amStatus        = -1;
    sss_status_t status = kStatus_SSS_Fail;
    smStatus_t smStatus = SM_NOT_OK;
    int listeningSock;
#ifdef ACCESS_MGR_UNIX_SOCKETS
    struct sockaddr_un server;
#else
    struct sockaddr_in server;
#endif
    uint16_t serverPort = SERVERPORT;

    // Client data structure
    client_t *clientHead = NULL;

    int fOnHold = 0;
    int fServe  = 1;
    int socketType;
    int yes = 1;
    uint8_t sndBuf[MSG_SIZE]; // Outgoing data sent over socket
    uint16_t sndBufLen = MSG_SIZE;
    uint8_t rcvBuf[MSG_SIZE];                 // Incoming data received over socket
    uint8_t respBuf[MSG_SIZE]          = {0}; // APDU Response buffer
    uint16_t respBufLen                = MSG_SIZE;
    static bool sessionOpen            = FALSE;
    uint8_t precookedCIP[]             = {0x01,
        0x04,
        0x63,
        0x07,
        0x00,
        0x93,
        0x02,
        0x08,
        0x00,
        0x02,
        0x03,
        0xE8,
        0x00,
        0x01,
        0x00,
        0x64,
        0x04,
        0x03,
        0xE8,
        0x00,
        0xFE,
        0x00};
    size_t precookedCIPLen             = sizeof(precookedCIP);
    uint8_t appletSelectCmd[]          = {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00};
    size_t appletSelectCmdLen          = sizeof(appletSelectCmd);
    uint8_t preCookedAppletSelectRsp[] = {0x90, 0x00};
    size_t preCookedAppletSelectRspLen = sizeof(preCookedAppletSelectRsp);
    nx_auth_type_t auth_type           = knx_AuthType_None;
    static bool requestAnyAddressBinding = FALSE;
    uint16_t connectStatus               = 0;
    ex_sss_boot_ctx_t boot_ctx           = {0};
    char portname[50]                    = {0};

    // Deal with command line arguments
    amStatus = amParseCmdLineArgs(argc, argv, &requestAnyAddressBinding);
    if (amStatus != AM_OK) {
        showAccessManagerHelp(argv);
        return EXIT_SUCCESS;
    }

    LOG_I("Starting accessManager (Rev.%d.%d).", ACCESS_MGR_VERSION_MAJOR, ACCESS_MGR_VERSION_MINOR);

    // Assign auth type based on build configurations
#if (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)
    auth_type = knx_AuthType_SIGMA_I_Verifier;
    LOG_I("Link between accessManager and secure authenticator is protected using SIGMA_I_Verifier authentication");
#endif

#if (SSS_HAVE_AUTH_SIGMA_I_PROVER)
    auth_type = knx_AuthType_SIGMA_I_Prover;
    LOG_I("Link between accessManager and secure authenticator is protected using SIGMA_I_Prover authentication");
#endif

#if (SSS_HAVE_AUTH_SYMM_AUTH)
    auth_type = knx_AuthType_SYMM_AUTH;
    LOG_I("Link between accessManager and secure authenticator is protected using symmetric authentication");
#endif

#if (SSS_HAVE_AUTH_NONE)
    auth_type = knx_AuthType_None;
    LOG_I("Link between accessManager and secure authenticator is unprotected");
#endif

    // Setup socket
    // NOTE: Linux defines two non-standard flags for the type parameter of the socket function
    // The SOCK_NONBLOCK flag (one of them) causes the kernel to set the O_NONBLOCK flag on the
    // underlying open file description, so that future I/O operations on the socket will be nonblocking.
    // This saves additional calls to fcntl() to achieve the same result.
    socketType = SOCK_STREAM;
#ifdef __gnu_linux__
    socketType |= SOCK_NONBLOCK;
#else
    LOG_E("Check whether listening socket must be non-blocking.");
#endif

#ifdef ACCESS_MGR_UNIX_SOCKETS
    listeningSock = socket(AF_UNIX, socketType, 0);
#else
    listeningSock = socket(AF_INET, socketType, 0);
#endif
    if (listeningSock < 0) {
        perror("socket");
        return MCS_SOCKET_FAILURE;
    }
    if (setsockopt(listeningSock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int))) {
        perror("setsockopt");
        close(listeningSock);
        return MCS_SOCKET_FAILURE;
    }
    memset(&server, 0x00, sizeof(server));

#ifdef ACCESS_MGR_UNIX_SOCKETS
    remove(UNIX_SOCKET_FILE);
    if (strlen(UNIX_SOCKET_FILE) > sizeof(server.sun_path) - 1) {
        perror("Socket File Path too long");
    }
    server.sun_family = AF_UNIX;
    strcpy(server.sun_path, UNIX_SOCKET_FILE);
#else
    server.sin_family = AF_INET;
    if (requestAnyAddressBinding) {
        server.sin_addr.s_addr = INADDR_ANY;
    }
    else {
        server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    server.sin_port = htons(serverPort);
#endif
    if (bind(listeningSock, (struct sockaddr *)&server, sizeof(server))) {
        perror("bind");
        close(listeningSock);
        return EXIT_FAILURE;
    }
    if (listen(listeningSock, BACKLOG)) {
        perror("listen");
        close(listeningSock);
        return EXIT_FAILURE;
    }

#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    LOG_I("accessManager JRCP_V1_AM (VCOM SE side)");
#elif defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    LOG_I("accessManager JRCP_V1_AM (T1oI2C_GP1_0 SE side)");
#else
#error "No valid SE side interconnect defined: supported are T1oI2C_GP1_0 and VCOM"
#endif

#ifdef ACCESS_MGR_UNIX_SOCKETS
    LOG_I("Server: waiting for connections.");
#else
    LOG_I("Server: waiting for connections on port %d.", serverPort);
#endif

#ifdef ACCESS_MGR_UNIX_SOCKETS
#else
    switch (ntohl(server.sin_addr.s_addr)) {
    case INADDR_LOOPBACK:
        LOG_W("Server: only localhost based processes can connect.");
        break;

    case INADDR_ANY:
        LOG_W("Server: accessManager is reachable over network ");
        break;

    default:
        LOG_W("Server: accessManager may be reachable over network ");
        break;
    }
#endif

    while (fServe == 1) {
        fd_set sockets;
        int maxfd = listeningSock;
        client_t *cl;
        int nStatus;
        int lockRequested = 0;
        bool sendToSA     = TRUE;

        /* create set of file descriptors (=sockets) */
        FD_ZERO(&sockets);
        FD_SET(listeningSock, &sockets);

        /* clean up list of clients */
        LOG_D("* clean up list of clients *");
        clientHead = amRemoveObsoleteClients(clientHead, &fOnHold);
        cl         = clientHead;

        while (cl != NULL) {
            if ((fOnHold == 1) && (cl->nLock > 0)) {
                // Only the locking client may listen on socket
                if (cl->sock >= 0) {
                    LOG_D("Adding socket %d (line=%d)", cl->sock, __LINE__);
                    FD_SET(cl->sock, &sockets);
                    maxfd = (maxfd > cl->sock) ? maxfd : cl->sock;
                }
            }
            else if (fOnHold == 0) {
                if (cl->sock >= 0) {
                    LOG_D("Adding socket %d (line=%d)", cl->sock, __LINE__);
                    FD_SET(cl->sock, &sockets);
                    maxfd = (maxfd > cl->sock) ? maxfd : cl->sock;
                }
            }
            cl = cl->next;
        }

        /* wait for new connections or data on existing connections */
        select(maxfd + 1, &sockets, NULL, NULL, NULL);

        /* look for data from clients */
        cl = clientHead;
        while ((cl != NULL) && (lockRequested != 1) && (fServe == 1)) {
            smStatus = SM_NOT_OK;
            if (FD_ISSET(cl->sock, &sockets)) {
                int nByte;
                int nPendingData = 0;

                // Read message header
                nByte = recv(cl->sock, rcvBuf, MSG_HEADER_SIZE, MSG_WAITALL);
                ENSURE_RECV_BYTES_OR_CLOSE_CONN_AND_CONTINUE(nByte, cl);

                nPendingData = (((uint16_t)rcvBuf[LNH_IDX] << 8) + (uint16_t)rcvBuf[LNL_IDX]) & 0x0FFFF;
                if (nPendingData > (MSG_SIZE - MSG_HEADER_SIZE)) {
                    LOG_E("rcvBuf too small to contain incoming command.");
                    close(cl->sock);
                    cl->sock = -1; /* mark client for deletion */
                    cl       = cl->next;
                    continue;
                }

                // Read the remaining bytes if any
                if (nPendingData > 0) {
                    nByte = recv(cl->sock, &rcvBuf[MSG_HEADER_SIZE], nPendingData, 0);
                    ENSURE_RECV_BYTES_OR_CLOSE_CONN_AND_CONTINUE(nByte, cl);
                }
                LOG_I("RX from client ID %d:", cl->sock);
                LOG_AU8_I(rcvBuf, nByte + MSG_HEADER_SIZE);

                switch (rcvBuf[MTY_IDX]) {
                case MTY_WAIT_FOR_CARD:
                    // Received CIP command, send the pre-cooked CIP response to client
                    LOG_I("CIP request received from client. Sending pre-cooked CIP to client");
                    memcpy(respBuf, precookedCIP, precookedCIPLen);
                    respBufLen = precookedCIPLen;
                    amStatus = amPackageApduResponse(MTY_WAIT_FOR_CARD, 0x00, respBuf, respBufLen, sndBuf, &sndBufLen);
                    if (amStatus != AM_OK) {
                        LOG_E("amPackageApduResponse failed!!");
                        close(cl->sock);
                        cl->sock = -1;
                        break;
                    }

                    LOG_I("TX to client ID %d:", cl->sock);
                    LOG_AU8_I(sndBuf, sndBufLen);
                    write(cl->sock, sndBuf, sndBufLen);

                    if (sessionOpen == FALSE) {
                        // Open a session one-time
                        LOG_I("Opening a session...");
                        status = amSessionOpen(argc, argv, &boot_ctx, auth_type, (char *)&portname);
                        if (status != kStatus_SSS_Success) {
                            LOG_E("amSessionOpen failed with status: 0x%04X.", status);
                            close(cl->sock);
                            cl->sock = -1;
                            break;
                        }
                        sessionOpen = TRUE;
                    }
                    else {
                        LOG_I("Session already open");
                    }

                    // Reset the buffers and lengths
                    amResetTransactionBuffers(rcvBuf, respBuf, &respBufLen, sndBuf, &sndBufLen);
                    break;

                case MTY_APDU_DATA:
                    // APDU received from client
                    LOG_I("Command Data Payload = %d", nPendingData);

                    if (sessionOpen == FALSE) {
                        // Open a session one-time
                        LOG_I("Opening a session...");
                        status = amSessionOpen(argc, argv, &boot_ctx, auth_type, (char *)&portname);
                        if (status != kStatus_SSS_Success) {
                            LOG_E("amSessionOpen failed with status: 0x%04X.", status);
                            close(cl->sock);
                            cl->sock = -1;
                            break;
                        }
                        sessionOpen = TRUE;
                    }
                    else {
                        LOG_I("Session already open");
                    }

                    if (0 == memcmp(&rcvBuf[MSG_HEADER_SIZE], appletSelectCmd, appletSelectCmdLen)) {
                        // Applet select request from client which was taken care of while opening session
                        // Send pre-cooked applet select response
                        LOG_I("Applet select request from client. Sending SW_OK (90 00) to client");
                        sendToSA = FALSE;
                        memcpy(respBuf, preCookedAppletSelectRsp, preCookedAppletSelectRspLen);
                        respBufLen = preCookedAppletSelectRspLen;
                        smStatus   = SM_OK;
                    }
                    else {
                        sendToSA = TRUE;
                    }

                    if (sendToSA) {
                        LOG_MAU8_I("APDU TX:", &rcvBuf[MSG_HEADER_SIZE], nPendingData);
                        smStatus = amTxRxAPDU(&((sss_nx_session_t *)&boot_ctx.session)->s_ctx,
                            &rcvBuf[MSG_HEADER_SIZE],
                            nPendingData,
                            respBuf,
                            &respBufLen,
                            auth_type);
                    }
                    if (smStatus != SM_OK) {
                        LOG_E("amTxRxAPDU failed with status: 0x%04X.", smStatus);
                        respBuf[0] = (U8)(smStatus >> 8);
                        respBuf[1] = (U8)(smStatus);
                        respBufLen = 2;
                    }
                    LOG_MAU8_I("APDU RX:", respBuf, respBufLen);

                    // Append header to received response and send to the client
                    amStatus = amPackageApduResponse(MTY_APDU_DATA, 0x00, respBuf, respBufLen, sndBuf, &sndBufLen);
                    if (amStatus != AM_OK) {
                        LOG_E("amPackageApduResponse failed!!");
                        close(cl->sock);
                        cl->sock = -1;
                        break;
                    }

                    LOG_I("TX to client ID %d:", cl->sock);
                    LOG_AU8_I(sndBuf, sndBufLen);
                    write(cl->sock, sndBuf, sndBufLen);

                    // Reset the buffers and lengths
                    amResetTransactionBuffers(rcvBuf, respBuf, &respBufLen, sndBuf, &sndBufLen);

                    // Close session in case APDU fails
                    if (smStatus != SW_OK) {
                        LOG_W("Closing the session. accessManager will reopen the session on next application request");
                        amSessionClose(&boot_ctx);
                        sessionOpen = FALSE;
                    }
                    break;

                case MTY_QUIT:
                    // Quit command received from client. Close the AM
                    LOG_W("Quit command received");

                    fServe          = 0;
                    sndBuf[MTY_IDX] = MTY_QUIT;
                    sndBuf[NAD_IDX] = rcvBuf[NAD_IDX];
                    sndBuf[LNH_IDX] = 0x00;
                    sndBuf[LNL_IDX] = 0x00;
                    sndBufLen       = MSG_HEADER_SIZE;

                    LOG_I("TX to client ID %d:", cl->sock);
                    LOG_AU8_I(sndBuf, sndBufLen);
                    write(cl->sock, sndBuf, sndBufLen);

                    LOG_I("Closing the session...");
                    amSessionClose(&boot_ctx);
                    break;

                default:
                    // Handle default case
                    LOG_E("Unrecognized message format received");
                    close(cl->sock);
                    cl->sock = -1;
                    break;
                }
            }
            cl = cl->next;
        }

        /* handle new client connections, if available */
        if (FD_ISSET(listeningSock, &sockets)) {
            struct sockaddr_in newClient;
            int newClientFd;
            socklen_t newClientLen = sizeof(struct sockaddr_in);

            newClientFd = accept(listeningSock, (struct sockaddr *)&newClient, &newClientLen);
            if (newClientFd < 0) {
                LOG_E("accept() failed.");
                return EXIT_FAILURE;
            }
            clientHead = addClient(clientHead, newClientFd); /* add client to list */

#ifdef ACCESS_MGR_UNIX_SOCKETS
            LOG_I("New client connection. Client ID: %d", newClientFd);
#else
            LOG_I("New client connection from %d.%d.%d.%d. Client ID: %d",
                (newClient.sin_addr.s_addr >> 0) & 0x000000ff,
                (newClient.sin_addr.s_addr >> 8) & 0x000000ff,
                (newClient.sin_addr.s_addr >> 16) & 0x000000ff,
                (newClient.sin_addr.s_addr >> 24) & 0x000000ff,
                newClientFd);
#endif
        }
    }
    LOG_W("Deleting all clients...");
    clientHead = amDeleteAllClients(clientHead);
    if (clientHead != NULL) {
        LOG_E("Unable to delete some clients");
    }
    LOG_I("Stopping server main program (Rev.%d.%d).", ACCESS_MGR_VERSION_MAJOR, ACCESS_MGR_VERSION_MINOR);
    return 0;
}

/*  HELPING FUNCTIONS  */

client_t *addClient(client_t *head, int sock)
{
    client_t *client = head;
    client_t *newClient;

    /* allocate memory for new client */
    newClient = (client_t *)malloc(sizeof(client_t));
    if (newClient == NULL) {
        LOG_E("Failed to add client; not enough memory!");
        exit(EXIT_FAILURE);
    }

    /* initialize client structure */
    memset(newClient, 0x00, sizeof(client_t));
    newClient->sock  = sock;
    newClient->nLock = 0;
    newClient->next  = NULL;

    /* if list is empty */
    if (head == NULL)
        return newClient;

    /* run to end of list */
    while (client->next != NULL)
        client = client->next;

    /* put client at the end of the list */
    client->next = newClient;

    return head;
}

client_t *amRemoveObsoleteClients(client_t *head, int *fOnHold)
{
    client_t *prevClient, *client;

    LOG_D("FN: %s", __FUNCTION__);

    while (head != NULL && head->sock < 0) {
        client_t *cl = head;

        head = head->next;
        free(cl);
    }

    if (head == NULL) { // if list is empty, return
        return head;
    }

    client     = head->next;
    prevClient = head;
    while (client != NULL) {
        if (client->sock < 0) {
            prevClient->next = client->next;
            free(client);
            client = prevClient;
        }
        prevClient = client;
        client     = client->next;
    }

    return head;
}

client_t *amDeleteAllClients(client_t *head)
{
    client_t *prevClient, *client;

    LOG_D("FN: %s", __FUNCTION__);

    while (head != NULL) {
        client_t *cl = head;

        head = head->next;
        free(cl);
    }
    return head;
}

int amPackageApduResponse(U8 messageType, U8 nodeAddress, U8 *payload, U16 payloadLen, U8 *targetBuf, U16 *targetBufLen)
{
    if ((UINT16_MAX - 4) < payloadLen) {
        LOG_E("payloadLen is too long");
        return AM_ARG_FAIL;
    }

    if (*targetBufLen < (4 + payloadLen)) {
        LOG_E("Target buffer provided too small.");
        return AM_ARG_FAIL;
    }

    targetBuf[0] = messageType;
    targetBuf[1] = nodeAddress;
    targetBuf[2] = (payloadLen >> 8) & 0x00FF;
    targetBuf[3] = payloadLen & 0x00FF;
    memcpy(&targetBuf[4], payload, payloadLen);
    *targetBufLen = 4 + payloadLen;
    return AM_OK;
}

void amResetTransactionBuffers(
    uint8_t *rcvBuf, uint8_t *respBuf, uint16_t *respBufLen, uint8_t *sndBuf, uint16_t *sndBufLen)
{
    memset(rcvBuf, 0, MSG_SIZE);
    memset(respBuf, 0, MSG_SIZE);
    *respBufLen = MSG_SIZE;
    memset(sndBuf, 0, MSG_SIZE);
    *sndBufLen = MSG_SIZE;
}

sss_status_t amSessionOpen(
    int argc, char **argv, ex_sss_boot_ctx_t *pboot_ctx, nx_auth_type_t auth_type, char *portName)
{
    sss_status_t status = kStatus_SSS_Fail;

    LOG_D("FN: %s", __FUNCTION__);
    amGetPortName(argc, argv, &portName);

    status = ex_sss_boot_open(pboot_ctx, portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_session_open Failed");
        goto cleanup;
    }

    if (kType_SSS_SubSystem_NONE == ((pboot_ctx)->session.subsystem)) {
        /* Nothing to do. Device is not opened
         * This is needed for the case when we open a generic communication
         * channel, without being specific to SE
         */
    }
    else {
        status = ex_sss_key_store_and_object_init((pboot_ctx));
        if (kStatus_SSS_Success != status) {
            LOG_E("ex_sss_key_store_and_object_init Failed");
            goto cleanup;
        }
    }

#if SSS_HAVE_HOSTCRYPTO_ANY
    ex_sss_boot_open_host_session((pboot_ctx));
#endif

    status = sss_key_store_context_init(&pboot_ctx->ks, &pboot_ctx->session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

cleanup:
    return status;
}

void amSessionClose(ex_sss_boot_ctx_t *pboot_ctx)
{
    LOG_D("FN: %s", __FUNCTION__);

    ex_sss_session_close(pboot_ctx);
}

/* Invoking command: accessManager <ADDRESS_BINDING> <PORT_NAME> [-h] [--help]
 * * <ADDRESS_BINDING>: local, remote
 * * <PORT_NAME>: Any supported port name that access manager will use to connect to SA
**/
int amParseCmdLineArgs(int argc, char **argv, bool *requestAnyAddressBinding)
{
    int status = -1;

    LOG_D("FN: %s", __FUNCTION__);

    if (argc == 1) {
        // Keep default values
        status = AM_OK;
    }
    else if (argc > 1) {
        if (strncmp(argv[argc - 1], "-h", strlen("-h")) == 0) {
            return -1;
        }
        else if (strncmp(argv[argc - 1], "--help", strlen("--help")) == 0) {
            return -1;
        }
        else if (strncmp(argv[1], "local", strlen("local")) == 0) {
            *requestAnyAddressBinding = FALSE;
        }
        else if (strncmp(argv[1], "remote", strlen("remote")) == 0) {
            *requestAnyAddressBinding = TRUE;
        }
        status = AM_OK;
    }
    return status;
}

void showAccessManagerHelp(char **argv)
{
    printf(
        "Access manager accepts the optional arguments [ADDRESS_BINDING] and [PORT_NAME]."
        " If no arguments are given, localhost binding is used with default port name.\n");
    printf("\n");
    printf("USAGE: %s [ADDRESS_BINDING] [PORT_NAME] [-h] [--help]\n", argv[0]);
    printf("\n");

    printf("[ADDRESS_BINDING]\n");
    printf("\tlocal: Only localhost connection accepted\n");
    printf("\tremote: Any supported connection accepted\n");
    printf("\n");
    printf("[PORT_NAME]: Any supported port name that access manager will use to connect to SA\n");
    printf("\n");

    printf("Example invocation:\n");
    printf("\t%s\n", argv[0]);
    printf("\t%s local\n", argv[0]);
    printf("\t%s remote /dev/i2c-1\n", argv[0]);
    printf("\n");

    printf("To view help:\n");
    printf("\t%s -h\n", argv[0]);
    printf("\t%s --help\n", argv[0]);
}

void amGetPortName(int argc, char **argv, char **pPortname)
{
    size_t len = 0;
    LOG_D("FN: %s", __FUNCTION__);

    // Check if last argument is not the ADDRESS_BINDING argument
    if (argc > 1 && (strncmp(argv[argc - 1], "local", strlen("local")) != 0) &&
        (strncmp(argv[argc - 1], "remote", strlen("remote")) != 0)) {
        // Last argument is considered as portname
        *pPortname = argv[argc - 1];
        LOG_I("Using portname = \"%s\" (from CLI)", *pPortname);
    }
    else {
        // Trying to get portname from the environment variable
        *pPortname = getenv(EX_SSS_BOOT_SSS_PORT);
        if (*pPortname == NULL) {
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
            // Assigning default COM port for VCOM
            *pPortname = (char *)gszCOMPortDefault;
            LOG_I("Using PortName='%s' (gszCOMPortDefault)", *pPortname);
#else
            // Otherwise do nothing and let it pass portname as NULL to session_open.
            // I2C library will assign a default port in this case.
            // PCSC is not supported on access manager. Skipping this part.
            LOG_I("Using default portname");
#endif
        }
        else {
            LOG_I("Using PortName = \"%s\" (from environment variable EX_SSS_BOOT_SSS_PORT)", *pPortname);
        }
    }
}