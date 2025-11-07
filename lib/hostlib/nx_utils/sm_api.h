/*
 *
 * Copyright 2018-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
* @par Description

*****************************************************************************/
#ifndef _SM_API_
#define _SM_API_

#include "sm_types.h"
#include "nx_HostLib_Ver.h"

#define AX_HOST_LIB_MAJOR (NX_HOSTLIB_VER_MAJOR) //!< Major number Host Library
#define AX_HOST_LIB_MINOR (NX_HOSTLIB_VER_MINOR) //!< Minor (High Nibble)/Patch number (Low Nibble) of Host Library
#define SE_CONNECT_TYPE_START 0x000

typedef enum
{
    kType_SE_Conn_Type_NONE = 0,
    /** Used for PC/OSX for virtual COM Port */
    kType_SE_Conn_Type_VCOM = SE_CONNECT_TYPE_START + 1,
    /** Used for T=1 over I2C for NX family */
    kType_SE_Conn_Type_T1oI2C = SE_CONNECT_TYPE_START + 2,
    /** - */
    kType_SE_Conn_Type_Channel = SE_CONNECT_TYPE_START + 3,
    /** Used for Use NFC Interface to talk to SE */
    kType_SE_Conn_Type_NFC = SE_CONNECT_TYPE_START + 4,
    /** Used for Use PCSC Interface to talk to SE */
    kType_SE_Conn_Type_PCSC = SE_CONNECT_TYPE_START + 5,
    /** Used for JRCP_V1_AM Interface to talk to JRCP_V1_AM server */
    kType_SE_Conn_Type_JRCP_V1_AM,
    /** - */
    kType_SE_Conn_Type_LAST,
    kType_SE_Conn_Type_SIZE = 0x7FFF
} SSS_Conn_Type_t;

#define SELECT_APPLET 0 //!< Select predefined applet
#define SELECT_NONE 1 //!< Don't issue a select
#define SELECT_SSD 2 //!< Select SSD
#define SELECT_APPLICATION 2 //!< Select Application

/**
 * Contains the information required to resume a connection with the Security Module.
 * Its content is only to be interpreted by the Host Library.
 * The semantics of the param1 and param2 fields depends on the link layer.
 */
typedef struct
{
    U16 connType;
    U16 param1; //!< Useage depends on link layer
    U16 param2; //!< Useage depends on link layer
    U16 hostLibVersion; //!< MSByte contains major version (::AX_HOST_LIB_MAJOR); LSByte contains minor version of HostLib (::AX_HOST_LIB_MINOR)
    U32 appletVersion; /*!< MSByte contains major version;
                              3 leading bits of LSByte contains minor version of Applet;
                              Last bit of LSByte encodes whether Applet is in Debug Mode, a '1' means 'Debug Mode' is available */
    U16 sbVersion;     //!< Expected to be 0x0000
    U8 select;         //!< Applet selection mode
    U8 sessionResume;  //!< Set to 1 to resume an open session with SE
} SmCommState_t;

/** \name Communication functions
   @{ */
U16 SM_Close(void *conn_ctx, U8 mode);
U16 SM_Connect(void *conn_ctx, SmCommState_t *commState, U8 *cip, U16 *cipLen);
U16 SM_ConnectWithAID(SmCommState_t *commState, U8 *appletAID, U16 appletAIDLen, U8 *cip, U16 *cipLen);
U16 SM_RjctConnect(void **conn_ctx, const char *connectString, SmCommState_t *commState, U8 *cip, U16 *cipLen);
U16 SM_RjctConnectWithAID(
    const char *connectString, SmCommState_t *commState, U8 *appletAID, U16 appletAIDLen, U8 *cip, U16 *cipLen);
U16 SM_I2CConnect(void **conn_ctx, SmCommState_t *commState, U8 *cip, U16 *cipLen, const char *pConnString);

U16 SM_SendAPDU(U8 *cmd, U16 cmdLen, U8 *resp, U16 *respLen);
U16 SM_I2CColdReset(void *conn_ctx);
#if defined(SMCOM_JRCP_V1_AM)
U16 SM_LockChannel();
U16 SM_UnlockChannel();
#endif

#if defined(SMCOM_JRCP_V1_AM)
#define SM_LOCK_CHANNEL() SM_LockChannel()
#define SM_UNLOCK_CHANNEL() SM_UnlockChannel()
#else
#define SM_LOCK_CHANNEL()
#define SM_UNLOCK_CHANNEL()
#endif

#endif //_SM_API_
