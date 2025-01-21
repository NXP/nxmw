/*
*
* Copyright 2022-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NX_APDU_TLV_H_INC
#define NX_APDU_TLV_H_INC

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "nx_enums.h"
#include "nx_const.h"
#include "nx_secure_msg_types.h"

#define NX_CLA_ISO 0x00
#define NX_CLA 0x90
#define NX_WRAP_CLA 0x94

typedef enum
{
    SM_NOT_OK                              = 0xFFFF,
    SM_OK                                  = 0x9000,
    SM_OK_ALT                              = 0x9100,
    SM_ERR_WRONG_LENGTH                    = 0x6700,
    SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985,
    SM_ERR_ACCESS_DENIED_BASED_ON_POLICY   = 0x6986,
    SM_ERR_SECURITY_STATUS                 = 0x6982,
    SM_ERR_WRONG_DATA                      = 0x6A80,
    SM_ERR_DATA_INAVILD                    = 0x6984,
    SM_ERR_FILE_FULL                       = 0x6A84,
    SM_ERR_FILE_PERMISSION_DENIED          = 0x919D,
    SM_ERR_FILE_PARAMETER                  = 0x919E,
    SM_ERR_FILE_AUTH                       = 0x91AE,
    SM_ERR_FILE_BOUNDARY                   = 0x91BE,
    SM_ERR_FILE_NOT_EXIST                  = 0x91F0,
    SM_ERR_FILE_DUPLICATE                  = 0x91DE,
} smStatus_t;

/** Certificate level */
typedef enum
{
    NX_CERTIFICATE_LEVEL_LEAF = 0x00,
    NX_CERTIFICATE_LEVEL_P1   = 0x01,
    NX_CERTIFICATE_LEVEL_P2   = 0x02,
    NX_CERTIFICATE_LEVEL_ROOT = 0x03,
} NX_CERTIFICATE_LEVEL_t;

/** Certificate level */
typedef enum
{
    NX_DATA_ITEM_LEAF           = 0x00,
    NX_DATA_ITEM_P1             = 0x01,
    NX_DATA_ITEM_P2             = 0x02,
    NX_DATA_ITEM_REPO_META_DATA = 0xFF,
} NX_DATA_ITEM_t;

/** Certificate level */
typedef enum
{
    NX_KEY_TYPE_AES128 = 0x02,
    NX_KEY_TYPE_AES256 = 0x03,
    NX_KEY_TYPE_NA     = 0xFF,
} NX_KEY_TYPE_t;

struct SeSession;

typedef struct SeSession
{
    nx_auth_type_t authType;

    smStatus_t (*fp_TXn)(struct SeSession *pSession,
        const tlvHeader_t *hdr,
        uint8_t *cmdHeader,
        size_t cmdHeaderLen,
        uint8_t *cmdData,
        size_t cmdDataLen,
        uint8_t *rsp,
        size_t *rspLen,
        uint8_t hasle,
        uint8_t isExtended,
        void *options);

    /** API called by fp_TXn. Helps handle EV2 secure messaging to transform buffer.
     * But this API never sends any data out over any communication link. */
    smStatus_t (*fp_Transform)(struct SeSession *pSession,
        const tlvHeader_t *inHdr,
        uint8_t *inCmdHeaderBuf,
        const size_t inCmdHeaderBufLen,
        uint8_t *inCmdDataBuf,
        const size_t inCmdDataBufLen,
        tlvHeader_t *outHdr,
        uint8_t *pTxBuf,
        size_t *pTxBufLen,
        uint8_t hasle,
        uint8_t isExtended,
        void *options);

    /* API called by fp_TXn. Helps handle Applet/Fast SCP to decrypt buffer.
    * But this API never reads any data */
    smStatus_t (*fp_DeCrypt)(struct SeSession *pSession,
        size_t cmd_cmacLen,
        uint8_t cmd,
        uint8_t *pInRxBuf,
        size_t *pInRxBufLen,
        uint8_t hasle,
        void *options);

    /* It's either a minimal/single implemntation that calls smCom_TransceiveRaw()
     * if pTunnelCtx is Null, directly call smCom_TransceiveRaw()
     * Or an API part of tunnel ctx that can do PlatformSCP */
    smStatus_t (*fp_RawTXn)(void *conn_ctx,
        nx_auth_type_t currAuth,
        const tlvHeader_t *hdr,
        uint8_t *cmdBuf,
        size_t cmdBufLen,
        uint8_t *rsp,
        size_t *rspLen,
        uint8_t hasle,
        uint8_t isExtended,
        void *options);

    smStatus_t (*fp_Transmit)(nx_auth_type_t currAuth,
        const tlvHeader_t *hdr,
        uint8_t *cmdBuf,
        size_t cmdBufLen,
        uint8_t *rsp,
        size_t *rspLen,
        uint8_t hasle);

    union {
        nx_auth_sigma_dynamic_ctx_t *pdynSigICtx;
        nx_auth_symm_dynamic_ctx_t *pdynSymmAuthCtx;
    } ctx;
    Nx_CommMode_t userCryptoCommMode; // user defined crypto request commmunication mode.
    /**Connection data context */
    void *conn_ctx;
} SeSession_t;

typedef SeSession_t *pSeSession_t;

typedef struct
{
    uint8_t negoMinVersion;
    uint8_t negoMaxVersion;
    uint8_t negoList[4];
    uint8_t negoListLen;
} Nx_ProtocolNegParams_t;

typedef struct
{
    uint8_t vendorID1;
    uint8_t hwType;
    uint8_t hwSubType;
    uint8_t hwMajorVersion;
    uint8_t hwMinorVersion;
    uint8_t hwStorageSize;
    uint8_t hwProtocol;

    uint8_t vendorID2;
    uint8_t swType;
    uint8_t swSubType;
    uint8_t swMajorVersion;
    uint8_t swMinorVersion;
    uint8_t swStorageSize;
    uint8_t swProtocol;

    uint8_t uidFormat; // UID Format definition
    uint8_t uidLength; // UID Length
    uint8_t uid[NX_VERSION_MAX_UID_LENGTH];
    uint32_t batchNo;  // FabKey Server Batch Number
    uint16_t fabKeyID; // FabKey identifier
    uint8_t cwProd;    // The calender week of production
    uint8_t yearProd;  // The year of production in BCD coding
    uint8_t fabID;     // Fab Identifier
} Nx_VersionParams_t;

typedef struct
{
    union {
        uint8_t keyID;
        uint8_t slotNum;
    } id;
    uint8_t length;
    uint8_t type;
} Nx_Crypto_AESIdParams_t;

typedef struct
{
    uint8_t repoID;
    uint8_t action;
} Nx_MgCertRepo_GetCommModeParams_t;

#pragma pack(push)
#pragma pack(1)
/** KeyID.ECCPrivateKeys meta-data */
typedef struct
{
    uint8_t keyNo;
    uint8_t curveID;
    uint16_t keyPolicy;
    uint8_t writeAccess;
    uint32_t keyUsageCtrLimit;
    uint32_t KeyUsageCtr;
} Nx_ECC_meta_data_t;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(1)
/** KeyID.CARootKeys meta-data */
typedef struct
{
    uint8_t keyNo;
    uint8_t curveID;
    uint16_t accessRights;
    uint8_t writeAccess;
    uint8_t reserved1;
    uint8_t reserved2;
} Nx_CARootKey_meta_data_t;
#pragma pack(pop)

/** RepoID.ReadCertRepo meta-data */
typedef struct
{
    uint8_t privateKeyId;
    uint16_t repoSize;
    uint8_t writeAccessCond;
    uint8_t readAccessCond;
} Nx_ReadCertRepo_meta_data_t;

typedef struct
{
    Nx_GPIOMgmtCfg_GPIOMode_t gpio1Mode;
    bool gpio1OutputInitStateHigh;
    bool gpio1PowerOutI2CEnabled;
    bool gpio1PowerOutBackpowerEnabled;
    bool gpio1DebounceFilterEnabled;
    uint16_t gpio1DebounceFilterValue;
    Nx_GPIOPadCfg_InputFilter_t gpio1InputFilterSelection;
    Nx_GPIOPadCfg_InputCfg_t gpio1InputCfg;
    Nx_GPIOPadCfg_OutputCfg_t gpio1OutputCfg;
    bool gpio1Supply1v1n1v2;
    Nx_GPIOMgmtCfg_GPIONotif_t gpio1OutputNotif;
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_t gpio1PowerOutDefaultTarget; // Targeted voltage/current level
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_t
        gpio1PowerOutInRushTarget;        // Initial current limit to handle the in rush of current
    uint16_t gpio1PowerOutInRushDuration; // The duration to apply the InRushTarget
    uint8_t
        gpio1PowerOutAdditionalCurrent; // The additional current required by Nx when supplying power harvesting. Resolution: 0.4mA.
    Nx_GPIOMgmtCfg_GPIOMode_t gpio2Mode;
    bool gpio2OutputInitStateHigh;
    bool gpio2PowerOutI2CEnabled;
    bool gpio2PowerOutBackpowerEnabled;
    bool gpio2DebounceFilterEnabled;
    uint16_t gpio2DebounceFilterValue;
    Nx_GPIOPadCfg_InputFilter_t gpio2InputFilterSelection;
    Nx_GPIOPadCfg_InputCfg_t gpio2InputCfg;
    Nx_GPIOPadCfg_OutputCfg_t gpio2OutputCfg;
    bool gpio2Supply1v1n1v2;
    Nx_GPIOMgmtCfg_GPIONotif_t gpio2OutputNotif;
    uint8_t gpio2OutputNFCPauseFileNo; /** FileNo of the File-Type.StandardData file for NFCPause */
    uint32_t
        gpio2OutputNFCPauseOffset; /** Starting offset of the section within the targeted file triggering NFCPause */
    uint32_t gpio2OutputNFCPauseLength; /** Length of the section within the targeted file */
    uint8_t acManage;                   // Access Condition Value for Cmd.ManageGPIO
    uint8_t acRead;                     // Access Condition Value for Cmd.ReadGPIO
} Nx_gpio_config_t;

typedef struct
{
    uint8_t index;
    uint8_t slotUsagePolicy;
    uint8_t algoPolicy;
} Nx_slot_buffer_policy_t;

#if defined(SSS_HAVE_LOG_VERBOSE) && (SSS_HAVE_LOG_VERBOSE)
#define DO_LOG_V(TAG, DESCRIPTION, VALUE) nLog("APDU", NX_LEVEL_DEBUG, #TAG " [" DESCRIPTION "] = 0x%X", VALUE);
#define DO_LOG_A(TAG, DESCRIPTION, ARRAY, ARRAY_LEN) \
    nLog_au8("APDU", NX_LEVEL_DEBUG, #TAG " [" DESCRIPTION "]", ARRAY, ARRAY_LEN);

#define NX_DO_LOG_V(DESCRIPTION, VALUE) nLog("APDU", NX_LEVEL_DEBUG, " [" DESCRIPTION "] = 0x%X", VALUE);
#define NX_DO_LOG_A(DESCRIPTION, ARRAY, ARRAY_LEN) \
    nLog_au8("APDU", NX_LEVEL_DEBUG, " [" DESCRIPTION "]", ARRAY, ARRAY_LEN);
#else
#define DO_LOG_V(TAG, DESCRIPTION, VALUE)
#define DO_LOG_A(TAG, DESCRIPTION, ARRAY, ARRAY_LEN)

#define NX_DO_LOG_V(DESCRIPTION, VALUE)
#define NX_DO_LOG_A(DESCRIPTION, ARRAY, ARRAY_LEN)
#endif

#define TLVSET_U8(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_U8(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

#define SET_U8(DESCRIPTION, PBUF, PBUFLEN, VALUE) \
    set_U8(PBUF, PBUFLEN, VALUE);                 \
    NX_DO_LOG_V(DESCRIPTION, VALUE)

#define TLVSET_U16(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_U16(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

#define SET_U16_LSB(DESCRIPTION, PBUF, PBUFLEN, VALUE) \
    set_U16_LSB(PBUF, PBUFLEN, VALUE);                 \
    NX_DO_LOG_V(DESCRIPTION, VALUE)

#define SET_U24_LSB(DESCRIPTION, PBUF, PBUFLEN, VALUE) \
    set_U24_LSB(PBUF, PBUFLEN, VALUE);                 \
    NX_DO_LOG_V(DESCRIPTION, VALUE)

#define GET_U24_LSB(DESCRIPTION, PBUF, PBUFLEN, VALUE) \
    get_U24_LSB(PBUF, PBUFLEN, VALUE);                 \
    NX_DO_LOG_V(DESCRIPTION, VALUE)

#define SET_U32_LSB(DESCRIPTION, PBUF, PBUFLEN, VALUE) \
    set_U32_LSB(PBUF, PBUFLEN, VALUE);                 \
    NX_DO_LOG_V(DESCRIPTION, VALUE)

#define GET_U32_LSB(DESCRIPTION, PBUF, PBUFLEN, VALUE) \
    get_U32_LSB(PBUF, PBUFLEN, VALUE);                 \
    NX_DO_LOG_V(DESCRIPTION, VALUE)

#define TLVSET_U16Optional(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_U16Optional(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

#define TLVSET_U64_SIZE(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE, SIZE) \
    tlvSet_U64_size(PBUF, PBUFLEN, TAG, VALUE, SIZE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

#define TLVSET_KeyID(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_KeyID(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

#define TLVSET_MaxAttemps(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_MaxAttemps(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

#define TLVSET_AttestationAlgo TLVSET_U8
#define TLVSET_CipherMode TLVSET_U8

#define TLVSET_ECCurve(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    tlvSet_ECCurve(PBUF, PBUFLEN, TAG, VALUE);                 \
    DO_LOG_V(TAG, DESCRIPTION, VALUE)

#define TLVSET_CryptoContext TLVSET_U8
#define TLVSET_CryptoModeSubType(DESCRIPTION, PBUF, PBUFLEN, TAG, VALUE) \
    TLVSET_U8(DESCRIPTION, PBUF, PBUFLEN, TAG, ((VALUE).union_8bit))

#define TLVSET_CryptoObjectID TLVSET_U16

#define TLVSET_u8buf(DESCRIPTION, PBUF, PBUFLEN, TAG, CMD, CMDLEN) \
    tlvSet_u8buf(PBUF, PBUFLEN, TAG, CMD, CMDLEN);                 \
    DO_LOG_A(TAG, DESCRIPTION, CMD, CMDLEN)

#define SET_u8buf(DESCRIPTION, PBUF, PBUFLEN, CMD, CMDLEN) \
    set_u8buf(PBUF, PBUFLEN, CMD, CMDLEN);                 \
    NX_DO_LOG_A(DESCRIPTION, CMD, CMDLEN)

#define TLVSET_u8bufOptional(DESCRIPTION, PBUF, PBUFLEN, TAG, CMD, CMDLEN) \
    tlvSet_u8bufOptional(PBUF, PBUFLEN, TAG, CMD, CMDLEN);                 \
    DO_LOG_A(TAG, DESCRIPTION, CMD, CMDLEN)

#define TLVSET_u8bufOptional_ByteShift(DESCRIPTION, PBUF, PBUFLEN, TAG, CMD, CMDLEN) \
    tlvSet_u8bufOptional_ByteShift(PBUF, PBUFLEN, TAG, CMD, CMDLEN);                 \
    DO_LOG_A(TAG, DESCRIPTION, CMD, CMDLEN)

int tlvSet_U8(uint8_t **buf, size_t *bufLen, NX_TAG_t tag, uint8_t value);
int tlvSet_u8buf(uint8_t **buf, size_t *bufLen, NX_TAG_t tag, const uint8_t *cmd, size_t cmdLen);
int tlvGet_U8(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, NX_TAG_t tag, uint8_t *pRsp);
int tlvGet_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, NX_TAG_t tag, uint8_t *rsp, size_t *pRspLen);
int tlvGet_u8bufPointer(
    uint8_t *buf, size_t *pBufIndex, const size_t bufLen, NX_TAG_t tag, uint8_t **rsp, size_t *pRspLen);
int tlvGet_ValueIndex(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, NX_TAG_t tag);

int set_U8(uint8_t **buf, size_t *bufLen, uint8_t value);
int set_U16_LSB(uint8_t **buf, size_t *bufLen, uint16_t value);
int set_U24_LSB(uint8_t **buf, size_t *bufLen, size_t value);
int get_U24_LSB(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint32_t *pRsp);
int set_U32_LSB(uint8_t **buf, size_t *bufLen, size_t value);
int get_U32_LSB(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint32_t *pRsp);
int set_u8buf(uint8_t **buf, size_t *bufLen, const uint8_t *cmd, size_t cmdLen);
int get_U8(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint8_t *pRsp);
int get_U16_LSB(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint16_t *pRsp);
int get_u8buf(uint8_t *buf, size_t *pBufIndex, const size_t bufLen, uint8_t *rsp, size_t rspLen);

smStatus_t nx_Transform_jrcpv1_am(struct SeSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    const size_t cmdHeaderLen,
    uint8_t *cmdDataBuf,
    const size_t cmdDataBufLen,
    tlvHeader_t *out_hdr,
    uint8_t *txBuf,
    size_t *ptxBufLen,
    uint8_t hasle,
    uint8_t isExtended,
    void *options);

smStatus_t nx_Transform(struct SeSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    const size_t cmdHeaderLen,
    uint8_t *cmdDataBuf,
    const size_t cmdDataBufLen,
    tlvHeader_t *out_hdr,
    uint8_t *txBuf,
    size_t *ptxBufLen,
    uint8_t hasle,
    uint8_t isExtended,
    void *options);

smStatus_t nx_DeCrypt(struct SeSession *pSessionCtx,
    size_t cmd_cmacLen,
    uint8_t cmd,
    uint8_t *rsp,
    size_t *rspLength,
    uint8_t hasle,
    void *options);

smStatus_t DoAPDUTx_s_Case3(SeSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    void *options);

smStatus_t DoAPDUTxRx_s_Case4(SeSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    void *options);

smStatus_t DoAPDUTxRx_s_Case4_ext(SeSession_t *pSessionCtx,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *rspBuf,
    size_t *pRspBufLen,
    void *options);

#if ((defined(SSS_HAVE_HOSTCRYPTO_ANY) && (SSS_HAVE_HOSTCRYPTO_ANY)) &&                \
     ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
         (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||  \
         (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) ||            \
         (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))))
smStatus_t nx_Transform_AES_EV2(struct SeSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    const size_t cmdHeaderLen,
    uint8_t *cmdData,
    const size_t cmdDataLen,
    tlvHeader_t *outhdr,
    uint8_t *txBuf,
    size_t *ptxBufLen,
    uint8_t hasle,
    uint8_t isExtended,
    void *options);
#endif // SSS_HAVE_HOSTCRYPTO_ANY && (either of one authentication)

#endif // !NX_APDU_TLV_H_INC
