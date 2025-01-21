/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file */

#ifndef NX_ENUMS_H
#define NX_ENUMS_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

/** Values for INS in ISO7816 APDU */
typedef enum
{
    /** Invalid */
    NX_INS_NA = 0,
    /** WrapAPDU command */
    NX_INS_WRAP = 0x41,
    /** Manage GPIOs*/
    NX_INS_MGNT_GPIO = 0x42,
    /** Read GPIOs */
    NX_INS_READ_GPIO = 0x43,
    /** GetKeySettings */
    NX_INS_GET_KEY_SETTINGS = 0x45,
    /** ManageKeyPair */
    NX_INS_MGMT_KEY_PAIR = 0x46,
    /** ManageCARootKey */
    NX_INS_MGMT_CA_ROOT_KEY = 0x48,
    /** ManageCertRepo */
    NX_INS_MGMT_CERT_REPO = 0x49,
    /** ReadCertRepo */
    NX_INS_READ_CERT_REPO = 0x4A,
    /** CryptoRequest  */
    NX_INS_CRYPTO_REQ = 0x4C,
    /** GetCardUID command*/
    NX_INS_GET_CARDUID = 0x51,
    /** SetConfiguration command*/
    NX_INS_SET_CONFIG = 0x5C,
    /** changeFileSettings */
    NX_INS_CHANGE_FILE_SETTING = 0x5F,
    /** Get version command */
    NX_INS_GET_VERSION = 0x60,
    /** GetISOFileIDs */
    NX_INS_GET_ISO_FILE_IDS = 0x61,
    /** GetKeyVersion */
    NX_INS_GET_KEY_VERSION = 0x64,
    /** GetConfiguration command */
    NX_INS_GET_CONFIG = 0x65,
    /** ActivateConfiguration command */
    NX_INS_ACTIVATE_CONFIG = 0x66,
    /** Free mem command */
    NX_INS_FREE_MEM = 0x6E,
    /** GetFileIDs */
    NX_INS_GET_FILE_IDS = 0x6F,
    /** AuthenticateEV2First */
    NX_INS_AUTHENTICATE_EV2_FIRST = 0x71,
    /** AuthenticateEV2nonFirst */
    NX_INS_AUTHENTICATE_EV2_NON_FIRST = 0x77,
    /** ISOInternalAuthenticate */
    NX_INS_ISO_INTERNAL_AUTH = 0x88,
    /** WriteData */
    NX_INS_WRITE_DATA = 0x8D,
    /** ISOSelectFile */
    NX_INS_ISO_SELECT_FILE = 0xA4,
    /** ReadData */
    NX_INS_READ_DATA = 0xAD,
    /** Additional frame request. */
    NX_INS_ADDITIONAL_FRAME_REQ = 0xAF,
    /** ISOReadBinary */
    NX_INS_ISO_READ_BINARY = 0xB0,
    /** Change Key. */
    NX_INS_CHANGE_KEY = 0xC4,
    /**CreateStdDataFile */
    NX_INS_CREATE_STD_DATA_FILE = 0xCD,
    /** CreateCounterFile */
    NX_INS_CREATE_COUNTER_FILE = 0xD0,
    /** ISOUpdateBinary */
    NX_INS_ISO_UPDATE_BINARY = 0xD6,
    /** ProcessSM */
    NX_INS_PROCESS_SM = 0xE5,
    /** GetFileSettings */
    NX_INS_GET_FILE_SETTINGS = 0xF5,
    /** GetFileCounters */
    NX_INS_GET_FILE_COUNTERS = 0xF6,
    /** IncrementCounterFile */
    NX_INS_INCREMENT_COUNTER_FILE = 0xF8,
    /** Mask for transient object creation, can only be combined with INS_WRITE. */
    NX_INS_TRANSIENT = 0x80,
    /** Mask for authentication object creation, can only be combined with INS_WRITE */
    NX_INS_AUTH_OBJECT = 0x40,
    /** Process session command */
    NX_INS_PROCESS = 0x05,
} NX_INS_t;

/** Values for P1 in ISO7816 APDU */
typedef enum
{
    /** Default P1 */
    NX_P1_DEFAULT = 0x00,
} NX_P1_t;

/** Values for P2 in ISO7816 APDU */
typedef enum
{
    /** Default P2 */
    NX_P2_DEFAULT = 0x00,
} NX_P2_t;

/** Different TAG Values to talk to Nx IoT Applet */
typedef enum
{
    /** Invalid */
    NX_TAG_NA                  = 0,
    NX_TAG_UNCOMPRESSED_CERT   = 0x21,
    NX_TAG_COMPRESSED_CERT     = 0x22,
    NX_TAG_AUTHDOHDR           = 0x7C,
    NX_TAG_CERT_DATA           = 0x7F,
    NX_TAG_CERT_REQ_LEAF       = 0x80,
    NX_TAG_OPTS_A              = 0x80,
    NX_TAG_CERT_REQ_P1         = 0x81,
    NX_TAG_RNDA                = 0x81,
    NX_TAG_RNDB                = 0x81,
    NX_TAG_CERT_REQ_P2         = 0x82,
    NX_TAG_SIG_B               = 0x82,
    NX_TAG_RANDOM_NUMBER       = 0x83,
    NX_TAG_KEY_SIZE            = 0x83,
    NX_TAG_CERT_HASH           = 0x84,
    NX_TAG_ECC_SIGNATURE       = 0x85,
    NX_TAG_EPHEM_PUB_KEY       = 0x86,
    NX_TAG_ENCRYPTED_PAYLOAD   = 0x87,
    NX_TAG_MSGI_PUBLIC_KEY     = 0xA0,
    NX_TAG_MSGI_HASH_AND_SIG   = 0xA1,
    NX_TAG_MSGI_CERT_REQUEST   = 0xA2,
    NX_TAG_MSGI_CERT_REPLY     = 0xA3,
    NX_TAG_MSGR_START_PROTOCOL = 0xB0,
    NX_TAG_MSGR_HASH_AND_SIG   = 0xB1,
    NX_TAG_MSGR_CERT_REQUEST   = 0xB2,
    NX_TAG_MSGR_CERT_REPLY     = 0xB3,
    NX_TAG_MSG_SESSION_OK      = 0xB4,
} NX_TAG_t;

/** Values for INS in ISO7816 APDU */
typedef enum
{
    /** Create Certificate Repository */
    NX_MgCertRepoINS_CreateRepo = 0x00,
    /** Load Certificate */
    NX_MgCertRepoINS_LoadCert = 0x01,
    /** Load Certificate Decompression Template */
    NX_MgCertRepoINS_LoadCertTemplate = 0x02,
    /** Load Certificate Mapping Information */
    NX_MgCertRepoINS_LoadCertMapping = 0x03,
    /** Activate Repository */
    NX_MgCertRepoINS_ActivateRepo = 0x04,
    /** Reset Certificate Repository */
    NX_MgCertRepoINS_ResetRepo = 0x05,
} NX_ManageCertRepo_t;

/** Different signature algorithms for EC */
typedef enum
{
    /** Invalid */
    kSE_ECSignatureAlgo_NA      = 0xFF,
    kSE_ECSignatureAlgo_SHA_256 = 0x00,
} SE_ECSignatureAlgo_t;

typedef enum
{
    /** Invalid */
    kSE_DigestOperate_NA       = 0,
    kSE_DigestOperate_INIT     = 0x01,
    kSE_DigestOperate_UPDATE   = 0x02,
    kSE_DigestOperate_FINALIZE = 0x03,
    kSE_DigestOperate_ONESHOT  = 0x04,
} SE_DigestOperate_t;

typedef enum
{
    /** Invalid */
    kSE_DigestMode_NA     = 0,
    kSE_DigestMode_SHA256 = 0x01,
    kSE_DigestMode_SHA384 = 0x02,
} SE_DigestMode_t;

typedef enum
{
    /** Invalid */
    kSE_ECSignOperate_NA           = 0,
    kSE_ECSignOperate_INIT         = 0x01,
    kSE_ECSignOperate_UPDATE       = 0x02,
    kSE_ECSignOperate_FINALIZE     = 0x03,
    kSE_ECSignOperate_ONESHOT      = 0x04,
    kSE_ECSignOperate_HASH_ONESHOT = 0x05,
} SE_ECSignOperate_t;

/** ECC Curve Identifiers */
typedef enum
{
    /** Invalid */
    Nx_ECCurve_NA           = 0x00,
    Nx_ECCurve_NIST_P256    = 0x0C,
    Nx_ECCurve_Brainpool256 = 0x0D,
} Nx_ECCurve_t;

typedef enum
{
    /** Fail */
    Nx_ECDHOption_SingleStep = 0x01,
    Nx_ECDHOption_TwoStep_1  = 0x02,
    Nx_ECDHOption_TwoStep_2  = 0x03,
} Nx_ECDHOption_t;

typedef enum
{
    /** Fail */
    Nx_ECVerifyResult_Init = 0x0000,
    Nx_ECVerifyResult_OK   = 0x5A5A,
    Nx_ECVerifyResult_Fail = 0xA5A5,
} Nx_ECVerifyResult_t;

/** Manage key pair option */
typedef enum
{
    Nx_MgtKeyPair_Act_Generate_Keypair = 0x00,
    Nx_MgtKeyPair_Act_Import_SK        = 0x01,
    Nx_MgtKeyPair_Act_Update_Meta      = 0x02,
} Nx_MgtKeyPair_Act_t;

/** Set configuration options list */
typedef enum
{
    Nx_ConfigOption_PICC_Config             = 0x00,
    Nx_ConfigOption_ATS_Update              = 0x02,
    Nx_ConfigOption_SAK_Update              = 0x03,
    Nx_ConfigOption_Secure_Msg_Config       = 0x04,
    Nx_ConfigOption_Capability_Data         = 0x05,
    Nx_ConfigOption_ATQA_Update             = 0x0C,
    Nx_ConfigOption_Silent_Mode_Config      = 0x0D,
    Nx_ConfigOption_Enhanced_Privacy_Config = 0x0E,
    Nx_ConfigOption_NFC_Mgmt                = 0x0F,
    Nx_ConfigOption_I2C_Mgmt                = 0x10,
    Nx_ConfigOption_GPIO_Mgmt               = 0x11,
    Nx_ConfigOption_ECC_Key_Mgmt            = 0x12,
    Nx_ConfigOption_Cert_Mgmt               = 0x13,
    Nx_ConfigOption_Watchdog_Mgmt           = 0x14,
    Nx_ConfigOption_Crypto_API_Mgmt         = 0x15,
    Nx_ConfigOption_Auth_Counter_Limit      = 0x16,
    Nx_ConfigOption_Halt_Wakeup_Config      = 0x17,
    Nx_ConfigOption_Defer_Config            = 0xFE,
    Nx_ConfigOption_Lock_Config             = 0xFF,
} Nx_ConfigOption_t;

/** Deferred options */
typedef enum
{
    Nx_ConfigDeferOption_PICC_Rnd_ID     = 0x00,
    Nx_Config_ChangeFileSettings_SDM_ENC = 0x01,
    Nx_ConfigDeferOption_Silent_Mode     = 0x0D,
    Nx_ConfigDeferOption_GPIO_Config     = 0x11,
} Nx_ConfigDeferOption_t;

typedef enum
{
    Nx_Conf_Deferral_Method_NoDeferral      = 0x00,
    Nx_Conf_Deferral_Method_NumBoot_1       = 0x01,
    Nx_Conf_Deferral_Method_NumBoot_2       = 0x02,
    Nx_Conf_Deferral_Method_NumBoot_3       = 0x03,
    Nx_Conf_Deferral_Method_NumBoot_4       = 0x04,
    Nx_Conf_Deferral_Method_NumBoot_5       = 0x05,
    Nx_Conf_Deferral_Method_NumBoot_6       = 0x06,
    Nx_Conf_Deferral_Method_NumBoot_7       = 0x07,
    Nx_Conf_Deferral_Method_Activate_Config = 0xFF,
    Nx_Conf_Deferral_Method_Invalid         = 0xE0,
} Nx_Defer_Conf_Method_t;

/** Get version options list */
typedef enum
{
    Nx_GetVersionOption_ReturnFabId = 0x01,
} Nx_GetVersionOption_t;

/** GPIO Number */
typedef enum
{
    Nx_GPIONo_1 = 0x00,
    Nx_GPIONo_2 = 0x01,
} Nx_GPIONumber_t;

/** GPIO output operation */
typedef enum
{
    Nx_GPIOOutput_Clear  = 0x00,
    Nx_GPIOOutput_Set    = 0x01,
    Nx_GPIOOutput_Toggle = 0x02,
} Nx_GPIO_OutputCtl_t;

/** GPIO power output operation */
typedef enum
{
    Nx_GPIOPowerOut_Default                    = 0x00,
    Nx_GPIOPowerOut_1800mV_100uA               = 0x01,
    Nx_GPIOPowerOut_1800mV_300uA               = 0x02,
    Nx_GPIOPowerOut_1800mV_500uA               = 0x03,
    Nx_GPIOPowerOut_1800mV_1000uA              = 0x04,
    Nx_GPIOPowerOut_1800mV_2000uA              = 0x05,
    Nx_GPIOPowerOut_1800mV_3000uA              = 0x06,
    Nx_GPIOPowerOut_1800mV_5000uA              = 0x07,
    Nx_GPIOPowerOut_1800mV_7000uA              = 0x08,
    Nx_GPIOPowerOut_1800mV_10000uA             = 0x09,
    Nx_GPIOPowerOut_1800mV_MaxAvailableCurrent = 0x0F,
    Nx_GPIOPowerOut_2000mV_100uA               = 0x11,
    Nx_GPIOPowerOut_2000mV_300uA               = 0x12,
    Nx_GPIOPowerOut_2000mV_500uA               = 0x13,
    Nx_GPIOPowerOut_2000mV_1000uA              = 0x14,
    Nx_GPIOPowerOut_2000mV_2000uA              = 0x15,
    Nx_GPIOPowerOut_2000mV_3000uA              = 0x16,
    Nx_GPIOPowerOut_2000mV_5000uA              = 0x17,
    Nx_GPIOPowerOut_2000mV_7000uA              = 0x18,
    Nx_GPIOPowerOut_2000mV_10000uA             = 0x19,
    Nx_GPIOPowerOut_2000mV_AvailableCurrent    = 0x1F,
} Nx_GPIO_PowerOut_Vol_t;

/** GPIO mode for GPIO Managemen Configuration */
typedef enum
{
    Nx_GPIOMgmtCfg_GPIOMode_Disabled           = 0x00,
    Nx_GPIOMgmtCfg_GPIOMode_Input              = 0x01,
    Nx_GPIOMgmtCfg_GPIOMode_Output             = 0x02,
    Nx_GPIOMgmtCfg_GPIOMode_InputTagTamper     = 0x03,
    Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut = 0x04,
    Nx_GPIOMgmtCfg_GPIOMode_NfcPausefileOut    = 0x05,
} Nx_GPIOMgmtCfg_GPIOMode_t;

/** GPIO input configuration */
typedef enum
{
    Nx_GPIOPadCfg_InputCfg_PlainInput_WeakPullUp   = 0x00,
    Nx_GPIOPadCfg_InputCfg_PlainInput_Repeater     = 0x01,
    Nx_GPIOPadCfg_InputCfg_PlainInput              = 0x02,
    Nx_GPIOPadCfg_InputCfg_PlainInput_WeakPullDown = 0x03,
    Nx_GPIOPadCfg_InputCfg_WeakPullUp              = 0x04,
    Nx_GPIOPadCfg_InputCfg_WPDN                    = 0x05,
    Nx_GPIOPadCfg_InputCfg_HighImpedance           = 0x06,
    Nx_GPIOPadCfg_InputCfg_WPD                     = 0x07,
} Nx_GPIOPadCfg_InputCfg_t;

/** GPIO input filter selection */
typedef enum
{
    Nx_GPIOPadCfg_InputFilter_Unfiltered_50ns  = 0x00,
    Nx_GPIOPadCfg_InputFilter_Unfiltered_10ns  = 0x01,
    Nx_GPIOPadCfg_InputFilter_ZIFfiltered_50ns = 0x02,
    Nx_GPIOPadCfg_InputFilter_ZIFfiltered_10ns = 0x03,
} Nx_GPIOPadCfg_InputFilter_t;

/** GPIO output configuration */
typedef enum
{
    Nx_GPIOPadCfg_OutputCfg_I2C_SF_FP_Tx_HS_Tx =
        0x00, // I2C S/F and FP transmit mode (SDA and SCL) and I2C HS transmit mode (only SDAH)
    Nx_GPIOPadCfg_OutputCfg_I2C_HS_Tx         = 0x01, // I2C HS transmit mode (only SCLK)
    Nx_GPIOPadCfg_OutputCfg_I2C_TX_SFFP       = 0x02,
    Nx_GPIOPadCfg_OutputCfg_I2C_TX_HS_SCLK    = 0x03,
    Nx_GPIOPadCfg_OutputCfg_GPIO_Low_Speed_1  = 0x04,
    Nx_GPIOPadCfg_OutputCfg_GPIO_Low_Speed_2  = 0x05,
    Nx_GPIOPadCfg_OutputCfg_GPIO_High_Speed_1 = 0x06,
    Nx_GPIOPadCfg_OutputCfg_GPIO_High_Speed_2 = 0x07,
    Nx_GPIOPadCfg_OutputCfg_Output_disabled   = 0x08,
} Nx_GPIOPadCfg_OutputCfg_t;

/** GPIO supply selection */
typedef enum
{
    Nx_GPIOMgmtCfg_SupplySelection_1V8_Signaling_I2C     = 0x00,
    Nx_GPIOMgmtCfg_SupplySelection_1V1_1V2_Signaling_I2C = 0x01,
} Nx_GPIOMgmtCfg_SupplySelection_t;

/** GPIO Notification */
typedef enum
{
    Nx_GPIOMgmtCfg_GPIONotif_Disabled = 0x00,
    Nx_GPIOMgmtCfg_GPIONotif_Auth     = 0x01,
    Nx_GPIOMgmtCfg_GPIONotif_NFC      = 0x02,
} Nx_GPIOMgmtCfg_GPIONotif_t;

/** GPIO default targeted current/voltage */
typedef enum
{
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_Disabled       = 0x00,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_100uA   = 0x01,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_300uA   = 0x02,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_500uA   = 0x03,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_1000uA  = 0x04,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_2000uA  = 0x05,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_3000uA  = 0x06,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_5000uA  = 0x07,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_7000uA  = 0x08,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_10000uA = 0x09,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_100uA   = 0x11,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_300uA   = 0x12,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_500uA   = 0x13,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_1000uA  = 0x14,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_2000uA  = 0x15,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_3000uA  = 0x16,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_5000uA  = 0x17,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_7000uA  = 0x18,
    Nx_GPIOMgmtCfg_VoltageCurrentLevel_2000mV_10000uA = 0x19,
} Nx_GPIOMgmtCfg_VoltageCurrentLevel_t;

/** GPIO in rush of current */
typedef enum
{
    Nx_GPIOMgmtCfg_GPIOxConfigA_Backpower_Enable = 0x01,
} Nx_GPIOMgmtCfg_GPIOxConfigA_t;

/** GPIO input status */
typedef enum
{
    Nx_GPIOInput_High    = 0x43,
    Nx_GPIOInput_Low     = 0x4F,
    Nx_GPIOInput_Invalid = 0x49,
} Nx_GPIOInput_Status_t;

/** GPIO Tag Tamper status */
typedef enum
{
    Nx_TagTamper_Close   = 0x43,
    Nx_TagTamper_Open    = 0x4F,
    Nx_TagTamper_Invalid = 0x49,
} Nx_TagTamper_Status_t;

typedef enum
{
    Nx_GPIO_STATUS_TT_CLOSE = 0x43,
    Nx_GPIO_STATUS_HIGH     = 0x48,
    Nx_GPIO_STATUS_LOW      = 0x4C,
    Nx_GPIO_STATUS_INVALID  = 0x49,
    Nx_GPIO_STATUS_TT_OPEN  = 0x4F,
} Nx_GPIO_Status_t;

/** Crypto API Operation */
typedef enum
{
    Nx_CryptoAPI_Operation_SHA                = 0x01,
    Nx_CryptoAPI_Operation_RNG                = 0x02,
    Nx_CryptoAPI_Operation_ECCSign            = 0x03,
    Nx_CryptoAPI_Operation_ECCVerify          = 0x04,
    Nx_CryptoAPI_Operation_ECDH               = 0x05,
    Nx_CryptoAPI_Operation_AES_CBC_ECB        = 0x06,
    Nx_CryptoAPI_Operation_Write_Int_Buffer   = 0x07,
    Nx_CryptoAPI_Operation_HMAC               = 0x08,
    Nx_CryptoAPI_Operation_HKDF               = 0x09,
    Nx_CryptoAPI_Operation_AES_CMAC_Sign      = 0x0A,
    Nx_CryptoAPI_Operation_AES_CMAC_Verify    = 0x0B,
    Nx_CryptoAPI_Operation_AES_Encrypt_Sign   = 0x0C,
    Nx_CryptoAPI_Operation_AES_Decrypt_Verify = 0x0D,
    Nx_CryptoAPI_Operation_ECHO               = 0xFD,
} Nx_CryptoAPI_Operation_t;

/** AES Operation **/
typedef enum
{
    Nx_AES_Operation_NA      = 0xFF,
    Nx_AES_Operation_Init    = 0x01,
    Nx_AES_Operation_Update  = 0x02,
    Nx_AES_Operation_Final   = 0x03,
    Nx_AES_Operation_OneShot = 0x04,
} Nx_AES_Operation_t;

/** AES Primitives **/
typedef enum
{
    Nx_AES_Primitive_NA                              = 0xFF,
    Nx_AES_Primitive_CBC_Encrypt                     = 0x03,
    Nx_AES_Primitive_CBC_Decrypt                     = 0x04,
    Nx_AES_Primitive_ECB_Encrypt                     = 0x05,
    Nx_AES_Primitive_ECB_Decrypt                     = 0x06,
    Nx_AES_Primitive_CCM_Encrypt_Sign                = 0x07,
    Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce = 0x08,
    Nx_AES_Primitive_CCM_Decrypt_Verify              = 0x09,
    Nx_AES_Primitive_GCM_Encrypt_Sign                = 0x0A,
    Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce = 0x0B,
    Nx_AES_Primitive_GCM_Decrypt_Verify              = 0x0C,
} Nx_AES_Primitive_t;

/** AES Verify Results **/
typedef enum
{
    Nx_AES_AEAD_Verify_Fail = 0xA5A5,
    Nx_AES_AEAD_Verify_OK   = 0x5A5A,
} Nx_AES_AEAD_Verify_Result_t;

/** CMAC and HMAC Operations **/
typedef enum
{
    Nx_MAC_Operation_NA         = 0xFF,
    Nx_MAC_Operation_Initialize = 0x01,
    Nx_MAC_Operation_Update     = 0x02,
    Nx_MAC_Operation_Finish     = 0x03,
    Nx_MAC_Operation_OneShot    = 0x04,
} Nx_MAC_Operation_t;

/** MAC Primitives **/
typedef enum
{
    Nx_MAC_Primitive_NA     = 0xFF,
    Nx_MAC_Primitive_Sign   = 0x01,
    Nx_MAC_Primitive_Verify = 0x02,
} Nx_MAC_Primitive_t;

/** MAC Verify Results **/
typedef enum
{
    Nx_MAC_Verify_Fail = 0xA5A5,
    Nx_MAC_Verify_OK   = 0x5A5A,
} Nx_MAC_Verify_Result_t;

/** HKDF Operation **/
typedef enum
{
    Nx_HKDFOperation_NA               = 0xFF,
    Nx_HKDFOperation_ExtractAndExpand = 0x00,
    Nx_HKDFOperation_Expand_Only      = 0x01,
} Nx_HKDFOperation_t;

/** Crypto API Data Source/Destination */
typedef enum
{
    /** Invalid */
    kSE_CryptoAESKey_TB_SLOTNUM_MIN = 0x80, // Min Transient buffer slot number for crypto key
    kSE_CryptoAESKey_TB_SLOTNUM_0   = 0x80,
    kSE_CryptoAESKey_TB_SLOTNUM_1   = 0x81,
    kSE_CryptoAESKey_TB_SLOTNUM_2   = 0x82,
    kSE_CryptoAESKey_TB_SLOTNUM_3   = 0x83,
    kSE_CryptoAESKey_TB_SLOTNUM_4   = 0x84,
    kSE_CryptoAESKey_TB_SLOTNUM_5   = 0x85,
    kSE_CryptoAESKey_TB_SLOTNUM_6   = 0x86,
    kSE_CryptoAESKey_TB_SLOTNUM_7   = 0x87,
    kSE_CryptoAESKey_TB_SLOTNUM_MAX = 0x87, // Min Transient buffer slot number for crypto key
    kSE_CryptoAESKey_SB_SLOTNUM_MIN = 0xC0, // Min Static buffer slot number for crypto key
    kSE_CryptoAESKey_SB_SLOTNUM_0   = 0xC0,
    kSE_CryptoAESKey_SB_SLOTNUM_1   = 0xC1,
    kSE_CryptoAESKey_SB_SLOTNUM_2   = 0xC2,
    kSE_CryptoAESKey_SB_SLOTNUM_3   = 0xC3,
    kSE_CryptoAESKey_SB_SLOTNUM_4   = 0xC4,
    kSE_CryptoAESKey_SB_SLOTNUM_5   = 0xC5,
    kSE_CryptoAESKey_SB_SLOTNUM_6   = 0xC6,
    kSE_CryptoAESKey_SB_SLOTNUM_7   = 0xC7,
    kSE_CryptoAESKey_SB_SLOTNUM_8   = 0xC8,
    kSE_CryptoAESKey_SB_SLOTNUM_9   = 0xC9,
    kSE_CryptoAESKey_SB_SLOTNUM_A   = 0xCA,
    kSE_CryptoAESKey_SB_SLOTNUM_B   = 0xCB,
    kSE_CryptoAESKey_SB_SLOTNUM_C   = 0xCC,
    kSE_CryptoAESKey_SB_SLOTNUM_D   = 0xCD,
    kSE_CryptoAESKey_SB_SLOTNUM_E   = 0xCE,
    kSE_CryptoAESKey_SB_SLOTNUM_F   = 0xCF,
    kSE_CryptoAESKey_SB_SLOTNUM_MAX = 0xCF, // Min Static buffer slot number for crypto key
} SE_CryptoAESKeySlotNum_t;

/** File type */
typedef enum
{
    Nx_FILEType_Standard = 0x00,
    Nx_FILEType_Counter  = 0x06,
    Nx_FILEType_NA       = 0xFF,
} Nx_FILEType_t;

/** Communication Modes */
typedef enum
{
    Nx_CommMode_Plain = 0x00,
    Nx_CommMode_MAC   = 0x01,
    Nx_CommMode_FULL  = 0x03,
    Nx_CommMode_NA    = 0x7F,
} Nx_CommMode_t;

/** Host Certificate Compression */
typedef enum
{
    Nx_HOSTCertCompress_Disabled = 0x01,
    Nx_HOSTCertCompress_Enabled  = 0x02,
    Nx_HOSTCertCompress_Dynamic  = 0x03,
} Nx_HOSTCertCompress_t;

/** Host Certificate Support */
typedef enum
{
    Nx_HostCertSupportFull = 0x01,
} Nx_HostCertSupport_t;

/** Internal Certificate Support */
typedef enum
{
    Nx_InternalCertSupportDefault = 0x00,
} Nx_InternalCertSupport_t;

/** Host Certificate Compression */
typedef enum
{
    Nx_SECertCompress_Default = 0x00,
} Nx_SECertCompress_t;

/** Access condition values */
typedef enum
{
    Nx_AccessCondition_Auth_Required_0x0 = 0x00,
    Nx_AccessCondition_Auth_Required_0x1 = 0x01,
    Nx_AccessCondition_Auth_Required_0x2 = 0x02,
    Nx_AccessCondition_Auth_Required_0x3 = 0x03,
    Nx_AccessCondition_Auth_Required_0x4 = 0x04,
    Nx_AccessCondition_Auth_Required_0x5 = 0x05,
    Nx_AccessCondition_Auth_Required_0x6 = 0x06,
    Nx_AccessCondition_Auth_Required_0x7 = 0x07,
    Nx_AccessCondition_Auth_Required_0x8 = 0x08,
    Nx_AccessCondition_Auth_Required_0x9 = 0x09,
    Nx_AccessCondition_Auth_Required_0xA = 0x0A,
    Nx_AccessCondition_Auth_Required_0xB = 0x0B,
    Nx_AccessCondition_Auth_Required_0xC = 0x0C,
    Nx_AccessCondition_Free_Over_I2C     = 0x0D,
    Nx_AccessCondition_Free_Access       = 0x0E,
    Nx_AccessCondition_No_Access         = 0x0F,
} Nx_AccessCondition_t;

/** SDMMetaRead Access condition values */
typedef enum
{
    Nx_SDMMetaRead_AccessCondition_Key_0x0        = 0x00,
    Nx_SDMMetaRead_AccessCondition_Key_0x1        = 0x01,
    Nx_SDMMetaRead_AccessCondition_Key_0x2        = 0x02,
    Nx_SDMMetaRead_AccessCondition_Key_0x3        = 0x03,
    Nx_SDMMetaRead_AccessCondition_Key_0x4        = 0x04,
    Nx_SDMMetaRead_AccessCondition_Plain_PICCData = 0x0E,
    Nx_SDMMetaRead_AccessCondition_No_PICCData    = 0x0F,
} Nx_SDMMetaRead_AccessCondition_t;

/** SDMFileRead Access condition values */
typedef enum
{
    Nx_SDMFileRead_AccessCondition_Key_0x0 = 0x00,
    Nx_SDMFileRead_AccessCondition_Key_0x1 = 0x01,
    Nx_SDMFileRead_AccessCondition_Key_0x2 = 0x02,
    Nx_SDMFileRead_AccessCondition_Key_0x3 = 0x03,
    Nx_SDMFileRead_AccessCondition_Key_0x4 = 0x04,
    Nx_SDMFileRead_AccessCondition_No_SDM  = 0x0F,
} Nx_SDMFileRead_AccessCondition_t;

/** Crypto API Data Source/Destination */
typedef enum
{
    /** Invalid */
    kSE_CryptoDataSrc_CommandBuf = 0x00, // Command buffer
    kSE_CryptoDataSrc_TB0        = 0x80, // Transient buffer slot number 0
    kSE_CryptoDataSrc_TB1        = 0x81, // Transient buffer slot number 1
    kSE_CryptoDataSrc_TB2        = 0x82, // Transient buffer slot number 2
    kSE_CryptoDataSrc_TB3        = 0x83, // Transient buffer slot number 3
    kSE_CryptoDataSrc_TB4        = 0x84, // Transient buffer slot number 4
    kSE_CryptoDataSrc_TB5        = 0x85, // Transient buffer slot number 5
    kSE_CryptoDataSrc_TB6        = 0x86, // Transient buffer slot number 6
    kSE_CryptoDataSrc_TB7        = 0x87, // Transient buffer slot number 7
    kSE_CryptoDataSrc_SB0        = 0xC0, // Static buffer slot number 0
    kSE_CryptoDataSrc_SB1        = 0xC1, // Static buffer slot number 1
    kSE_CryptoDataSrc_SB2        = 0xC2, // Static buffer slot number 2
    kSE_CryptoDataSrc_SB3        = 0xC3, // Static buffer slot number 3
    kSE_CryptoDataSrc_SB4        = 0xC4, // Static buffer slot number 4
    kSE_CryptoDataSrc_SB5        = 0xC5, // Static buffer slot number 5
    kSE_CryptoDataSrc_SB6        = 0xC6, // Static buffer slot number 6
    kSE_CryptoDataSrc_SB7        = 0xC7, // Static buffer slot number 7
    kSE_CryptoDataSrc_SB8        = 0xC8, // Static buffer slot number 8
    kSE_CryptoDataSrc_SB9        = 0xC9, // Static buffer slot number 9
    kSE_CryptoDataSrc_SBA        = 0xCA, // Static buffer slot number 10
    kSE_CryptoDataSrc_SBB        = 0xCB, // Static buffer slot number 11
    kSE_CryptoDataSrc_SBC        = 0xCC, // Static buffer slot number 12
    kSE_CryptoDataSrc_SBD        = 0xCD, // Static buffer slot number 13
    kSE_CryptoDataSrc_SBE        = 0xCE, // Static buffer slot number 14
    kSE_CryptoDataSrc_SBF        = 0xCF, // Static buffer slot number 15
} SE_CryptoDataSrc_t;

/** Selection Control */
typedef enum
{
    Nx_ISOSelectCtl_MF_DF_EF_ID = 0x00, // Select MF, DF or EF, by file identifier
    Nx_ISOSelectCtl_CHILD_DF    = 0x01, // Select child DF
    Nx_ISOSelectCtl_EF_UNDER_DF = 0x02, // Select EF under the current DF, by file identifier
    Nx_ISOSelectCtl_Parent_DF   = 0x03, // Select parent DF of the current DF
    Nx_ISOSelectCtl_DF_Name     = 0x04, // Select by DF name
} Nx_ISOSelectCtl_t;

/** ISOSelectFile P2 */
typedef enum
{
    Nx_ISOSelectCtl_RET_FCI = 0x00, // Return FCI template
    Nx_ISOSelectCtl_NO_FCI  = 0x0C, // No response data: no FCI shall be returned
} Nx_ISOSelectOpt_t;

/** ProcessSM Action */
typedef enum
{
    Nx_ProcessSM_Action_Apply  = 0x01,
    Nx_ProcessSM_Action_Remove = 0x02,
} Nx_ProcessSM_Action_t;

/** ProcessSM Operation */
typedef enum
{
    Nx_ProcessSM_Operation_Oneshot = 0x04,
} Nx_ProcessSM_Operation_t;

/** ProcessSM Operation */
typedef enum
{
    Nx_GetKeySettingOpt_CryptoKey  = 0x00,
    Nx_GetKeySettingOpt_ECCPrivKey = 0x01,
    Nx_GetKeySettingOpt_CARootKey  = 0x02,
} Nx_GetKeySettingOpt_t;

/** AC BITMAP Shift */
typedef enum
{
    Nx_AC_Bitmap_0_Shift  = 0x00,
    Nx_AC_Bitmap_1_Shift  = 0x01,
    Nx_AC_Bitmap_2_Shift  = 0x02,
    Nx_AC_Bitmap_3_Shift  = 0x03,
    Nx_AC_Bitmap_4_Shift  = 0x04,
    Nx_AC_Bitmap_5_Shift  = 0x05,
    Nx_AC_Bitmap_6_Shift  = 0x06,
    Nx_AC_Bitmap_7_Shift  = 0x07,
    Nx_AC_Bitmap_8_Shift  = 0x08,
    Nx_AC_Bitmap_9_Shift  = 0x09,
    Nx_AC_Bitmap_10_Shift = 0x0A,
    Nx_AC_Bitmap_11_Shift = 0x0B,
    Nx_AC_Bitmap_12_Shift = 0x0C,
    Nx_AC_Bitmap_13_Shift = 0x0D,
} Nx_AC_BITMAP_t;

#define NX_KEY_SETTING_ECC_KEY_NO_OFFSET 0

#endif /* NX_ENUMS_H */
