/*
 * Copyright 2010-2014, 2018-2020, 2022-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _PHNXPESEPROTO7816_3_H_
#define _PHNXPESEPROTO7816_3_H_
#include <phNxpEse_Internal.h>

/**
 * \addtogroup ISO7816-3_protocol_lib
 * \brief 7816-3 PROTOCOL STACK
 * @{ */

/********************* Definitions and structures *****************************/

/*!
 * \brief S-Frame types used in 7816-3 protocol stack
 */
typedef enum sFrameTypes
{
    RESYNCH_REQ = 0x00, /*!< Re-synchronisation request between host and ESE */
    RESYNCH_RSP = 0x20, /*!< Re-synchronisation response between host and ESE */
    IFSC_REQ    = 0x01, /*!< IFSC size request */
    IFSC_RES    = 0x21, /*!< IFSC size response */
    ABORT_REQ   = 0x02, /*!< Abort request */
    ABORT_RES   = 0x22, /*!< Abort response */
    WTX_REQ     = 0x03, /*!< WTX request */
    WTX_RSP     = 0x23, /*!< WTX response */
#if defined(T1oI2C_GP1_0) || defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    SWR_REQ        = 0x0F, /*!< Software reset request */
    SWR_RSP        = 0x2F, /*!< Software reset response */
    COLD_RESET_REQ = 0x1E, /*cold reset request*/
    COLD_RESET_RES = 0x3E, /*cold reset response*/
    RELEASE_REQ    = 0x06, /* Release  request*/
    RELEASE_RES    = 0x26, /* Release  response*/
    CIP_REQ        = 0x04, /*!< Get CIP request */
    CIP_RES        = 0x24, /*!< Get CIP response */
#endif
    DEEP_PWR_DOWN_REQ = 0x1F, /*deep power down*/
    DEEP_PWR_DOWN_RES = 0x3F, /*deep power down*/
    INVALID_REQ_RES           /*!< Invalid request */
} sFrameTypes_t;

/*!
 * \brief R-Frame types used in 7816-3 protocol stack
 */
typedef enum rFrameTypes
{
    RACK  = 0x01, /*!< R-frame Acknowledgement frame indicator */
    RNACK = 0x02  /*!< R-frame Negative-Acknowledgement frame indicator */
} rFrameTypes_t;

/*!
 * \brief R-Frame error types used 7816-3 protocol stack
 */
typedef enum rFrameErrorTypes
{
    NO_ERROR,         /*!< R-frame received with success */
    PARITY_ERROR,     /*!< R-frame received with parity error */
    OTHER_ERROR,      /*!< R-frame received with Other error */
    SOF_MISSED_ERROR, /*!< R-frame received with frame missing error */
    UNDEFINED_ERROR   /*!< R-frame received with some undefined error */
} rFrameErrorTypes_t;

/*!
 * \brief Frame types used in 7816-3 protocol stack
 */
typedef enum phNxpEseProto7816_FrameTypes
{
    IFRAME,  /*!< Frame type: I-frame */
    SFRAME,  /*!< Frame type: S-frame */
    RFRAME,  /*!< Frame type: R-frame */
    INVALID, /*!< Frame type: Invalid */
    UNKNOWN  /*!< Frame type: Unknown */
} phNxpEseProto7816_FrameTypes_t;

/*!
 * \brief 7816-3 protocol stack states
 */
typedef enum phNxpEseProto7816_State
{
    PH_NXP_ESE_PROTO_7816_IDLE,       /*!< 7816-3 protocol state: IDLE */
    PH_NXP_ESE_PROTO_7816_TRANSCEIVE, /*!< 7816-3 protocol state: TRANSCEIVE going on */
    PH_NXP_ESE_PROTO_7816_DEINIT      /*!< 7816-3 protocol state: DeInit going on */
} phNxpEseProto7816_State_t;

/*!
 * \brief 7816-3 protocol transceive states
 */
typedef enum phNxpEseProto7816_TransceiveStates
{
    IDLE_STATE,   /*!< 7816-3 protocol transceive state: IDLE */
    SEND_IFRAME,  /*!< 7816-3 protocol transceive state: I-frame to be sent */
    SEND_R_NACK,  /*!< 7816-3 protocol transceive state: R-NACK frame to be sent */
    SEND_R_ACK,   /*!< 7816-3 protocol transceive state: R-ACK frame to be sent */
    SEND_S_RSYNC, /*!< 7816-3 protocol transceive state: S-frame re-synchronisation command to be sent */
#if defined(T1oI2C_GP1_0) || defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    SEND_S_SWR,      /*!< 7816-3 protocol transceive state: S-frame Software reset command to be sent */
    SEND_S_RELEASE,  /*!< 7816-3 protocol transceive state: S-frame RELEASE command to be sent */
    SEND_S_CIP,      /*!< 7816-3 protocol transceive state: S-frame CIP command to be sent */
    SEND_S_COLD_RST, /*!< 7816-3 protocol transceive state: S-frame cold reset command to be sent */
#endif
    SEND_S_WTX_REQ,     /*!< 7816-3 protocol transceive state: S-frame WTX command to be sent */
    SEND_S_WTX_RSP,     /*!< 7816-3 protocol transceive state: S-frame WTX response to be sent */
    SEND_DEEP_PWR_DOWN, /*!< Deep power down */
} phNxpEseProto7816_TransceiveStates_t;

/*!
 * \brief I-frame information structure for ISO 7816-3
 *
 * This structure holds the  information of I-frame used for sending
 * and receiving the frame packet.
 *
 */
typedef struct iFrameInfo
{
    bool_t isChained;    /*!< I-frame: Indicates if more frames to follow in the same data packet or not */
    uint8_t *p_data;     /*!< I-frame: Actual data (Information field (INF)) */
    uint8_t seqNo;       /*!< I-frame: Sequence number of the I-frame */
    uint32_t maxDataLen; /*!< I-frame: Maximum data length to be allowed in a single I-frame */
    uint32_t dataOffset; /*!< I-frame: Offset to the actual data(INF) for the current frame of the packet */
    uint32_t
        totalDataLen; /*!< I-frame: Total data left in the packet, used to set the chained flag/calculating offset */
    uint32_t sendDataLen; /*!< I-frame: the length of the I-frame actual data */
} iFrameInfo_t;

/*!
 * \brief S-frame information structure for ISO 7816-3
 *
 * This structure holds the  information of S-frame used for sending
 * and receiving the frame packet.
 *
 */
typedef struct sFrameInfo
{
    sFrameTypes_t sFrameType; /*!< S-frame: Type of S-frame cmd/rsp */
} sFrameInfo_t;

/*!
 * \brief R-frame information structure for ISO 7816-3
 *
 * This structure holds the  information of R-frame used for sending
 * and receiving the frame packet.
 *
 */
typedef struct rFrameInfo
{
    uint8_t seqNo;              /*!< R-frame: Sequence number of the expected I-frame */
    rFrameErrorTypes_t errCode; /*!< R-frame: Error type */
} rFrameInfo_t;

/*!
 * \brief Next/Last Tx information structure holding transceive data
 *
 * This structure holds the information of the next/last sent
 * I-frame/R-frame/S-frame depending on the frame type
 *
 */
typedef struct phNxpEseProto7816_NextTx_Info
{
    //union {
    iFrameInfo_t
        IframeInfo; /*!< Information of the I-frame to be send next or the last sent I-frame depending on the frame type */
    rFrameInfo_t
        RframeInfo; /*!< Information of the R-frame to be send next or the last sent R-frame depending on the frame type */
    sFrameInfo_t
        SframeInfo; /*!< Information of the S-frame to be send next or the last sent S-frame depending on the frame type */
                    //} f;
    phNxpEseProto7816_FrameTypes_t FrameType; /*!< Frame (I/R/S frames) type to be sent next */
} phNxpEseProto7816_NextTx_Info_t;

/*!
 * \brief Last sent Tx ransceive data
 *
 * This structure holds the information of the last sent
 * I-frame/R-frame/S-frame
 *
 */
typedef phNxpEseProto7816_NextTx_Info_t phNxpEseProto7816_LastTx_Info_t;

/*!
 * \brief Last Rx information structure holding transceive data
 *
 * This structure holds the information of the next/last sent
 * I-frame/R-frame/S-frame
 *
 */
typedef struct phNxpEseRx_Cntx
{
    iFrameInfo_t lastRcvdIframeInfo;                  /*!< I-frame: Last received frame */
    rFrameInfo_t lastRcvdRframeInfo;                  /*!< R-frame: Last received frame */
    sFrameInfo_t lastRcvdSframeInfo;                  /*!< S-frame: Last received frame */
    phNxpEseProto7816_FrameTypes_t lastRcvdFrameType; /*!< Last received frame type */
    phNxpEse_data *pRsp;
    size_t responseBytesRcvd;
} phNxpEseRx_Cntx_t;

/*!
 * \brief 7816-3 protocol stack context structure
 *
 * This structure holds the complete information of the
 * 7816-3 protocol stack context
 *
 */
typedef struct phNxpEseProto7816
{
    phNxpEseProto7816_LastTx_Info_t phNxpEseLastTx_Cntx; /*!< Last transmitted frame information */
    phNxpEseProto7816_NextTx_Info_t phNxpEseNextTx_Cntx; /*!< Next frame to be transmitted */
    phNxpEseRx_Cntx_t phNxpEseRx_Cntx;                   /*!< Last received frame information */
    phNxpEseProto7816_TransceiveStates_t
        phNxpEseProto7816_nextTransceiveState;                /*!< Next Transceive state. It determines the next
                                                                                                                                         action to be done from host */
    phNxpEseProto7816_State_t phNxpEseProto7816_CurrentState; /*!< Current protocol stack state */
    uint8_t
        recoveryCounter; /*!< Keeps track of number of error recovery done. Stack exits after it reaches max. count  */
    unsigned long int wtx_counter_limit; /*!< Max. WTX counter limit */
    unsigned long int wtx_counter;       /*!< WTX count tracker */
    uint8_t timeoutCounter; /*!< Keeps track of number of timeout happened. Stack exits after it reaches max. count  */
    phNxpEseProto7816_FrameTypes_t
        lastSentNonErrorframeType; /*!< Copy of the last sent non-error frame type: R-ACK, S-frame, I-frame */
    unsigned long int rnack_retry_limit;
    unsigned long int rnack_retry_counter;
} phNxpEseProto7816_t;

/*!
 * \brief 7816-3 protocol stack init params
 *
 * This structure holds the parameters to be passed to open 7816-3 protocl stack instance
 *
 */
typedef struct phNxpEseProto7816InitParam
{
    unsigned long int wtx_counter_limit; /*!< WTX count limit */
    bool_t interfaceReset;               /*!< INTF reset required or not>*/
    unsigned long int rnack_retry_limit;
} phNxpEseProto7816InitParam_t;

/*!
 * \brief 7816-3 protocol PCB bit level structure
 *
 * This structure holds the bit level information of PCB byte
 * as per 7816-3 protocol
 *
 */
typedef struct phNxpEseProto7816_PCB_bits
{
    uint8_t lsb : 1;  /*!< PCB: lsb */
    uint8_t bit2 : 1; /*!< PCB: bit2 */
    uint8_t bit3 : 1; /*!< PCB: bit3 */
    uint8_t bit4 : 1; /*!< PCB: bit4 */
    uint8_t bit5 : 1; /*!< PCB: bit5 */
    uint8_t bit6 : 1; /*!< PCB: bit6 */
    uint8_t bit7 : 1; /*!< PCB: bit7 */
    uint8_t msb : 1;  /*!< PCB: msb */
} phNxpEseProto7816_PCB_bits_t;

/*!
 * \brief 7816_3 protocol stack instance
 */
//phNxpEseProto7816_t phNxpEseProto7816_3_Var;

/*!
 * \brief Max. size of the frame that can be sent
 */
#define IFSC_SIZE_SEND 254
/*!
 * \brief Delay to be used before sending the next frame, after error reported by ESE
 */
#define DELAY_ERROR_RECOVERY 3500
/*!
 * \brief 7816-3 protocol frame header length
 */
#if defined(T1oI2C_GP1_0) || defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
#define PH_PROTO_7816_HEADER_LEN 0x04 // LEN field is 2 byte
#endif                                // SSS_HAVE_SMCOM_T1OI2C_GP1_0
/*!
 * \brief 7816-3 protocol frame CRC length
 */
#define PH_PROTO_7816_CRC_LEN 0x02
/*!
 * \brief 7816-3 Chaining flag bit for masking
 */
#define PH_PROTO_7816_CHAINING 0x20
/*!
 * \brief 7816-3 frame length offset
 */
#define PH_PROPTO_7816_FRAME_LENGTH_OFFSET 0x02
/*!
 * \brief 7816-3 S-block request command mask
 */
#define PH_PROTO_7816_S_BLOCK_REQ 0xC0
/*!
 * \brief 7816-3 S-block response mask
 */
#define PH_PROTO_7816_S_BLOCK_RSP 0xE0
/*!
 * \brief 7816-3 S-block reset command mask
 */
#define PH_PROTO_7816_S_RESET 0x0F
/*!
 * \brief 7816-3 S-block End of APDU cmd mask
 */
#define PH_PROTO_7816_S_END_OF_APDU 0x05
/*!
 * \brief 7816-3 S-block WTX mask
 */
#define PH_PROTO_7816_S_WTX 0x03
/*!
 * \brief 7816-3 S-block re-sync mask
 */
#define PH_PROTO_7816_S_RESYNCH 0x00
/*!
 * \brief 7816-3 protocol max. error retry counter
 */
#define PH_PROTO_7816_FRAME_RETRY_COUNT 10
/*!
 * \brief 7816-3 protocol max. WTX default count
 */
#define PH_PROTO_WTX_DEFAULT_COUNT 500
/*!
 * \brief 7816-3 protocol max. timeout retry count
 */
#define PH_PROTO_7816_TIMEOUT_RETRY_COUNT 1
/*!
 * \brief 7816-3 to represent magic number zero
 */
#define PH_PROTO_7816_VALUE_ZERO 0x00
/*!
 * \brief 7816-3 to represent magic number one
 */
#define PH_PROTO_7816_VALUE_ONE 0x01
/*!
 * \brief 7816-3 for max retry for CRC error
 */
#define MAX_RNACK_RETRY_LIMIT 0x02
/*!
 * \brief 7816-3 S-block chip reset mask
 */
#if defined(T1oI2C_GP1_0) || defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
#define PH_PROTO_7816_S_COLD_RST 0x1E
#endif
/*!
 * \brief 7816-3 S-block get atr mask
 */
#define PH_PROTO_7816_S_GET_ATR 0x07
/*!
 * \brief 7816-3 S-block deep power down
 */
#define PH_PROTO_7816_S_DEEP_PWR_DOWN 0x1F
/*!
 * \brief 7816-3 S-block software reset mask
 */
#define PH_PROTO_7816_S_SWR 0x0F
/*!
 * \brief 7816-3 S-block release cmd mask
 */
#define PH_PROTO_7816_S_RELEASE 0x06
/*!
 * \brief 7816-3 S-block get CIP cmd mask
 */
#define PH_PROTO_7816_S_GET_CIP 0x04

/* T=1 protocol Block format for T1oI2C
 ___________________________________________________________________________________________________
|       Prologue Filed (Mandatory)       | Information Field (Optional)| Epilogue Filed (Mandatory) |
|________________________________________|_____________________________|____________________________|
|NAD(1 byte) | PCB(1 byte) | LEN(1 byte) |      INF(LEN bytes)         |        CRC(2 bytes)        |                                                                     |
|____________|_____________|_____________|_____________________________|____________________________|                                                                       |
*/

/* T=1 protocol Block format for T1oI2C GP
 ___________________________________________________________________________________________________
|       Prologue Filed (Mandatory)       | Information Field (Optional)| Epilogue Filed (Mandatory) |
|________________________________________|_____________________________|____________________________|
|NAD(1 byte) | PCB(1 byte) | LEN(2 byte) |      INF(LEN bytes)         |        CRC(2 bytes)        |                                                                     |
|____________|_____________|_____________|_____________________________|____________________________|                                                                       |
*/

#define PH_PROPTO_7816_NAD_OFFSET 0
#define PH_PROPTO_7816_PCB_OFFSET 1
#define PH_PROPTO_7816_LEN_UPPER_OFFSET 2
#define PH_PROPTO_7816_LEN_LOWER_OFFSET 3 /* for GP lower byte will be a part of T=1 protocol frame*/
#define PH_PROPTO_7816_INF_BYTE_OFFSET (PH_PROTO_7816_HEADER_LEN)

/*!
 * \brief Start of frame marker
 * \ communication Direction      NAD value
 * \ SE host to SE                  0x5A
 * \ SE to SE host                  0xA5
 * \ eUICC host to Euicc            0x4B
 * \ eUICC to eUICC host            0xB4
 */
#define SEND_PACKET_SOF 0x21
/*!
 * \Retrieve Information Filed from 7816-3 T=1 protocol frame
 * NAD   -1 byte
 * PCB   -1 byte
 * LEN   -(1 or 3 bytes for UM11225) & (2 bytes for GP)
 * CRC16 -2 bytes
 */
#define PH_PROTO_7816_INF_FILED (PH_PROTO_7816_HEADER_LEN + PH_PROTO_7816_CRC_LEN)
/*
 * APIs exposed from the 7816-3 protocol layer
 */

bool_t phNxpEseProto7816_Close(void *conn_ctx);
bool_t phNxpEseProto7816_Open(void *conn_ctx, phNxpEseProto7816InitParam_t initParam, phNxpEse_data *AtrRsp);
bool_t phNxpEseProto7816_Transceive(void *conn_ctx, phNxpEse_data *pCmd, phNxpEse_data *pRsp);
bool_t phNxpEseProto7816_Reset(void);
bool_t phNxpEseProto7816_SetIfscSize(uint16_t IFSC_Size);
bool_t phNxpEseProto7816_ResetProtoParams(void);
bool_t phNxpEseProto7816_Store(phNxpEseProto7816_t *conn_ctx);
bool_t phNxpEseProto7816_Retrieve(phNxpEseProto7816_t *conn_ctx);

#if defined(T1oI2C_GP1_0) || defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
bool_t phNxpEseProto7816_SoftReset(void *conn_ctx);
bool_t phNxpEseProto7816_GetCip(void *conn_ctx, phNxpEse_data *pRsp);
bool_t phNxpEseProto7816_ColdReset(void *conn_ctx);
bool_t phNxpEseProto7816_Release_Req(void *conn_ctx);
bool_t phNxpEseProto7816_Deep_Pwr_Down(void *conn_ctx);
#endif
uint8_t getMaxSupportedSendIFrameSize(void);
/** @} */
#endif /* _PHNXPESEPROTO7816_3_H_ */
