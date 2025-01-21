/*
 *
 * Copyright 2022-2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
/** @file */

#ifndef _FSL_SSS_CONFIG_OPTION_H_
#define _FSL_SSS_CONFIG_OPTION_H_

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

/** @defgroup sss_config_option Config_option
 *
 * Options for configurations.
 */

/** @addtogroup sss_config_option
 * @{ */

typedef struct
{
    /** Enable Support ECC-based Unilateral Authentication (Originality Checking) */
    uint8_t unilateralEnabled : 1;
    /** Enable Support Import of ECC Private Key */
    uint8_t importECCEnabled : 1;
    /** Enable Enforce User Data Files 1k Limit */
    uint8_t userData1kLimitEnabled : 1;
    /** Enable Counter Support */
    uint8_t counterEnabled : 1;
    /** Enable EC DSA 4.0 */
    uint8_t ecdsav4Enabled : 1;
    /** Enable CCM AES-256 Secure Channel */
    uint8_t ccmEnabled : 1;
    /** Enable NTAG AES-256 Secure Channel */
    uint8_t ntagAES256Enabled : 1;
    /** Enable NTAG AES-128 Secure Channel */
    uint8_t ntagAES128Enabled : 1;
    /** Enable External Crypto API ECC Support */
    uint8_t eccEnabled : 1;
    /** Enable External Crypto API AES Support */
    uint8_t aesEnabled : 1;
    /** Enable GPIO Support */
    uint8_t gpioEnabled : 1;
    /** Enable I2C IO Support */
    uint8_t i2cEnabled : 1;
    /** Enable NFC Support */
    uint8_t nfcEnabled : 1;
} sss_config_mfrFeature_u;

typedef struct
{
    /** Enable ISO random ID */
    uint8_t useRID : 1;
} sss_config_PICC_u;

typedef struct
{
    /** User defined ATS */
    uint8_t userATS[20];
    size_t userATSLen;
} sss_config_userATS_u;

typedef struct
{
    /** User defined SAK1 and SAK2 */
    uint8_t sak1;
    uint8_t sak2;
} sss_config_userSAK_u;

typedef struct
{
    /** In VCState.AuthenticatedAES and VCState.AuthenticatedECC,
    disable chained writing with Cmd.WriteData in CommMode.MAC
    and CommMode.Full. */
    uint8_t disableChainWrite : 1;
} sss_config_SMConfig_u;

typedef struct
{
    /** User configured PDCap2.5 and PDCap2.6 */
    uint8_t PDCap2_5;
    uint8_t PDCap2_6;
} sss_config_capData_u;

typedef struct
{
    /** User defined ATQA */
    uint16_t userATQA;
} sss_config_atqa_u;

typedef struct
{
    /** Silent mode options */
    uint8_t customREQSEnabled : 1;
    uint8_t silentModeEnabled : 1;
    uint8_t REQS;
    uint8_t WUPS;
} sss_config_silentMode_u;

typedef struct
{
    uint8_t originalityCheckDisabled : 1; // Originality Check disabling
    uint8_t manuDataMaskEnabled : 1;      // Manufacturer data masking
    uint8_t appPrivacyKeyEnabled : 1;     // KeyID.AppPrivacyKey enabling
    uint8_t appPrivacyKey;                // KeyID.AppPrivacyKey definition
} sss_config_enhancedPrivacy_u;

typedef struct
{
    uint8_t ecdsav4Enabled : 1;        // MFi 4.0 ECDSA
    uint8_t sigIVerifierEnbaled : 1;   // Enable SIGMA-I Verifier
    uint8_t sigIProverEnbaled : 1;     // Enable SIGMA-I Prover
    uint8_t securetunnelAES256 : 1;    // secure Tunnel strength for sigma-i authentication AES-256
    uint8_t securetunnelAES128 : 1;    // secure Tunnel strength for sigma-i authentication AES-128
    uint8_t ntagEv2Disabled : 1;       // Enable NTAG EV2 secure messaging
    uint8_t ev2AES256 : 1;             // Secure Tunnel strength AES256 or AES128
    uint8_t cardUnilateralEnbaled : 1; // ECC-based Card-Unilateral Authentication
    uint8_t symmAuthEnbaled : 1;       // AES-based Symmetric Authentication
} sss_config_protocolOptions_t;

typedef struct
{
    uint8_t negoMinVersion; // Minimum version to use in protocol negotiation
    uint8_t negoMaxVersion; // Maximum version to use in protocol negotiation
    uint8_t negoList[4];    // Ordered list of supported protocols.
    uint8_t negoListLen;    // The number of crypto protocols supported
} sss_config_protocolNegParams_t;

typedef struct
{
    uint8_t nfcSupport : 1;                       // NFC Support
    sss_config_protocolOptions_t protocolOptions; // The crypto protocols supported over NFC.
} sss_config_nfcMgmt_u;

typedef struct
{
    uint8_t i2cSupport : 1; // I2C Support
    uint8_t i2cAddr;
    sss_config_protocolOptions_t protocolOptions; // The crypto protocols supported over I2C.
} sss_config_i2cMgmt_u;

/** GPIO mode for GPIO Managemen Configuration */
typedef enum
{
    sss_GPIOMgmtCfg_PlainInput_WeakPullUp   = 0x00,
    sss_GPIOMgmtCfg_PlainInput_Repeater     = 0x01,
    sss_GPIOMgmtCfg_PlainInput              = 0x02,
    sss_GPIOMgmtCfg_PlainInput_WeakPullDown = 0x03,
} sss_config_gpio_plain_input_t;

/** GPIO voltage/current level for GPIO power out Configuration */
typedef enum
{
    sss_GPIOPowerOut_1800mV_100uA   = 0x01,
    sss_GPIOPowerOut_1800mV_300uA   = 0x02,
    sss_GPIOPowerOut_1800mV_500uA   = 0x03,
    sss_GPIOPowerOut_1800mV_1000uA  = 0x04,
    sss_GPIOPowerOut_1800mV_2000uA  = 0x05,
    sss_GPIOPowerOut_1800mV_3000uA  = 0x06,
    sss_GPIOPowerOut_1800mV_5000uA  = 0x07,
    sss_GPIOPowerOut_1800mV_7000uA  = 0x08,
    sss_GPIOPowerOut_1800mV_10000uA = 0x09,
    sss_GPIOPowerOut_2000mV_100uA   = 0x11,
    sss_GPIOPowerOut_2000mV_300uA   = 0x12,
    sss_GPIOPowerOut_2000mV_500uA   = 0x13,
    sss_GPIOPowerOut_2000mV_1000uA  = 0x14,
    sss_GPIOPowerOut_2000mV_2000uA  = 0x15,
    sss_GPIOPowerOut_2000mV_3000uA  = 0x16,
    sss_GPIOPowerOut_2000mV_5000uA  = 0x17,
    sss_GPIOPowerOut_2000mV_7000uA  = 0x18,
    sss_GPIOPowerOut_2000mV_10000uA = 0x19,
} sss_config_gpio_power_out_t;

/**  */
typedef struct
{
    /** Debounce filter */
    uint8_t debounceFilterEnabled : 1;
    sss_config_gpio_plain_input_t weakPullup;
    uint16_t debounceFilterValue;
} sss_config_gpio_mgmt_input_u;

typedef struct
{
    /** Speed Selection */
    uint8_t highSpeedMode : 1;
} sss_config_gpio_mgmt_output_u;

typedef struct
{
    uint8_t targetedVoltage; // Targeted voltage/current level
} sss_config_gpio_mgmt_powerOut_u;

/** GPIO mode for GPIO Managemen Configuration */
typedef enum
{
    sss_GPIOMgmtCfg_GPIOMode_Disabled           = 0x00,
    sss_GPIOMgmtCfg_GPIOMode_Input              = 0x01,
    sss_GPIOMgmtCfg_GPIOMode_Output             = 0x02,
    sss_GPIOMgmtCfg_GPIOMode_InputTagTamper     = 0x03,
    sss_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut = 0x04,
    sss_GPIOMgmtCfg_GPIOMode_NfcPausefileOut    = 0x05,
} sss_config_gpio_mgmt_mode_t;

typedef struct
{
    /** GPIO Mode */
    sss_config_gpio_mgmt_mode_t gpioMode;

    /** Union of applicable policies based on the type of object
     */
    union {
        sss_config_gpio_mgmt_input_u input;
        sss_config_gpio_mgmt_output_u output;
        sss_config_gpio_mgmt_powerOut_u powerOut;
    } gpioConfig;
} sss_config_gpio_mgmt_cfg;

/** GPIO Mode */
typedef enum
{
    sss_GPIOMgmtCfg_GPIONotif_Disabled = 0x00,
    sss_GPIOMgmtCfg_GPIONotif_GPIO1    = 0x01,
    sss_GPIOMgmtCfg_GPIONotif_GPIO2    = 0x02,
} sss_config_gpio_mgmt_notif;

/** GPIO in rush of current */
typedef enum
{
    sss_GPIOMgmtCfg_InRushTarget_Disabled       = 0x00,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_100uA   = 0x01,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_300uA   = 0x02,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_500uA   = 0x03,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_1000uA  = 0x04,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_2000uA  = 0x05,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_3000uA  = 0x06,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_5000uA  = 0x07,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_7000uA  = 0x08,
    sss_GPIOMgmtCfg_InRushTarget_1800mV_10000uA = 0x09,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_100uA   = 0x11,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_300uA   = 0x12,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_500uA   = 0x13,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_1000uA  = 0x14,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_2000uA  = 0x15,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_3000uA  = 0x16,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_5000uA  = 0x17,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_7000uA  = 0x18,
    sss_GPIOMgmtCfg_InRushTarget_2000mV_10000uA = 0x19,
} sss_config_gpio_mgmt_in_rush_target;

/** Communication Modes */
typedef enum
{
    sss_CommMode_Plain = 0x00,
    sss_CommMode_MAC   = 0x01,
    sss_CommMode_FULL  = 0x03,
} sss_comm_mode_t;

/** Communication Modes */
typedef enum
{
    sss_AccessCondition_Free_Over_I2C = 0x0D,
    sss_AccessCondition_Free          = 0x0E,
    sss_AccessCondition_Never         = 0x0F,
} sss_access_condition_t;

typedef struct
{
    sss_config_gpio_mgmt_cfg gpio1Cfg;    // GPIO 1 Mode
    sss_config_gpio_mgmt_cfg gpio2Cfg;    // GPIO 2 Mode
    sss_config_gpio_mgmt_notif gpioNotif; // GPIO notification on authentication
    sss_comm_mode_t commModeManage;       // CommMode for Cmd.ManageGPIO
    uint8_t acManage;                     // Access Condition Value for Cmd.ManageGPIO
    sss_comm_mode_t commModeRead;         // CommMode for Cmd.ReadGPIO
    uint8_t acRead;                       // Access Condition Value for Cmd.ReadGPIO
    sss_config_gpio_mgmt_in_rush_target inRushTarget;
    uint16_t inRushDuration;
    uint8_t additionalCurrent;
    uint8_t NFCPauseFileNo;  // FileNo of the FileType.StandardData file for NFCPause
    uint32_t NFCPauseOffset; // Starting offset of the section within the targeted file triggering NFCPause
    uint32_t
        NFCPauseLength; // Length of the section within the targeted file starting at NFCPAuseOffset triggering NFCPause
} sss_config_gpio_mgmt_u;

typedef struct
{
    sss_comm_mode_t commMode_ManageKeyPair;   // CommMode for Cmd.ManageKeyPair
    uint8_t ac_ManageKeyPair;                 // Access Condition Value for Cmd.ManageKeyPair
    sss_comm_mode_t commMode_ManageCARootKey; // CommMode for Cmd.ManageCARootKey
    uint8_t ac_ManageCARootKey;               // Access Condition Value for Cmd.ManageCARootKey
    uint32_t kucLimit;                        // keyusagectr Value for Cmd.ManageKeyPair
} sss_config_eccKeyMgmt_u;

/** Host Certificate Compression */
typedef enum
{
    sss_HOSTCertCompress_Disabled = 0x01,
    sss_HOSTCertCompress_Enabled  = 0x02,
    sss_HOSTCertCompress_Dynamic  = 0x03,
} sss_config_certMgmt_hostCompress_t;

/** Device Certificate Compression */
typedef enum
{
    sss_SECertCompress_Default = 0x00,
} sss_config_certMgmt_deviceCompress_t;

typedef struct
{
    uint8_t leafCacheSize;
    uint8_t intermCacheSize;
    sss_config_certMgmt_hostCompress_t hostCertCompress;
    sss_config_certMgmt_deviceCompress_t deviceCertCompress;
    uint8_t sigICacheEnabled : 1;
    uint8_t commMode_ManageCertRepo; // CommMode for Cmd.ManageCertRepo
    uint8_t ac_ManageCertRepo;       // Access Condition Value for Cmd.ManageCertRepo
} sss_config_certMgmt_u;

typedef struct
{
    uint8_t HWDTValue;
    uint8_t AWDT1Value;
    uint8_t AWDT2Value;
} sss_config_watchdogMgmt_u;

typedef struct
{
    uint8_t asymCryptoAPIEnabled : 1;
    uint8_t symCryptoAPIEnabled : 1;
    uint8_t commMode_CryptoRequest;          // CommMode for Cmd.CryptoRequest
    uint8_t ac_CryptoRequest;                // Access Condition Value for Cmd.CryptoRequest
    uint8_t changeAC_KeyID_CryptoRequestKey; // Access condition for Cmd.ChangeKey targeting KeyID.CryptoRequestKey.
    uint8_t TBPolicyCount;
    uint8_t TBPolicy[SSS_TB_POLICY_MAX_COUNT * SSS_POLICY_BUF_SIZE];
    uint8_t SBPolicyCount;
    uint8_t SBPolicy[SSS_SB_POLICY_MAX_COUNT * SSS_POLICY_BUF_SIZE];
} sss_config_cryptoAPIMgmt_u;

typedef struct
{
    uint8_t lockMap[3];
} sss_config_lockCfg_u;

/** Type of configuration options */
typedef enum
{
    sss_ConfigOption_PICC_Config             = 0x00,
    sss_ConfigOption_ATS_Update              = 0x02,
    sss_ConfigOption_SAK_Update              = 0x03,
    sss_ConfigOption_Secure_Msg_Config       = 0x04,
    sss_ConfigOption_Capability_Data         = 0x05,
    sss_ConfigOption_ATQA_Update             = 0x0C,
    sss_ConfigOption_Silent_Mode_Config      = 0x0D,
    sss_ConfigOption_Enhanced_Privacy_Config = 0x0E,
    sss_ConfigOption_NFC_Mgmt                = 0x0F,
    sss_ConfigOption_I2C_Mgmt                = 0x10,
    sss_ConfigOption_GPIO_Mgmt               = 0x11,
    sss_ConfigOption_ECC_Key_Mgmt            = 0x12,
    sss_ConfigOption_Cert_Mgmt               = 0x13,
    sss_ConfigOption_Watchdog_Mgmt           = 0x14,
    sss_ConfigOption_Crypto_API_Mgmt         = 0x15,
    sss_ConfigOption_Manufacture_Feature     = 0xD0,
    sss_ConfigOption_Lock_Config             = 0xFF,
} sss_config_type_t;

/** Type of policy */
typedef struct
{
    /** Configuration options Type */
    sss_config_type_t type;

    /** Union of applicable policies based on the type of object
     */
    union {
        sss_config_mfrFeature_u mfrFeature;
        sss_config_PICC_u picc;
        sss_config_userATS_u ats;
        sss_config_userSAK_u userSAK;
        sss_config_SMConfig_u smConfig;
        sss_config_capData_u capData;
        sss_config_atqa_u atqa;
        sss_config_silentMode_u silentMode;
        sss_config_enhancedPrivacy_u enhancedPrivacy;
        sss_config_nfcMgmt_u nfcMgmt;
        sss_config_i2cMgmt_u i2cMgmt;
        sss_config_gpio_mgmt_u gpioMgmt;
        sss_config_eccKeyMgmt_u ecKeyMgmt;
        sss_config_certMgmt_u certMgmt;
        sss_config_watchdogMgmt_u watchdogMgmt;
        sss_config_cryptoAPIMgmt_u cryptoAPIMgmt;
        sss_config_lockCfg_u lockCfg;
    } config;
} sss_cfg_option_t;

/** @} */

#endif /* _FSL_SSS_CONFIG_OPTION_H_ */
