/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include <string.h>
#include "nx_apdu.h"
#include "nx_enums.h"
#include "nx_const.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */
#define USER_ATS_MAX_LEN 20
#define LOCK_MAP_MAX_LEN 3

static ex_sss_boot_ctx_t gex_sss_get_config_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_get_config_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                             = kStatus_SSS_Fail;
    smStatus_t sm_status                            = SM_NOT_OK;
    sss_nx_session_t *pSession                      = NULL;
    uint16_t productFeature                         = 0;
    uint8_t PICCConfig                              = 0;
    uint8_t userATS[USER_ATS_MAX_LEN]               = {0};
    size_t userATSLen                               = 0;
    uint8_t sak1                                    = 0;
    uint8_t sak2                                    = 0;
    uint8_t SMConfigA                               = 0;
    uint8_t SMConfigB                               = 0;
    uint8_t CapDataBuf[NX_CONF_CAPABILITY_DATA_LEN] = {0};
    uint8_t CapDataBufLen                           = sizeof(CapDataBuf);
    uint16_t userATQA                               = 0;
    uint8_t silentMode                              = 0;
    uint8_t REQS                                    = 0;
    uint8_t WUPS                                    = 0;
    uint8_t appPrivacyKey                           = 0;
    uint8_t privacyOption                           = 0;
    uint8_t nfcSupport                              = NX_CONF_NFC_ENABLED;
    uint16_t protocolOptions                        = 0;
    uint8_t i2cSupport                              = NX_CONF_I2C_DISABLED;
    uint8_t i2cAddr                                 = 0;
    Nx_gpio_config_t gpioConfig                     = {0};
    uint8_t keyAC                                   = 0;
    uint8_t rootKeyAC                               = 0;
    uint8_t leafCacheSize                           = 0;
    uint8_t intermCacheSize                         = 0;
    uint8_t acManageCertRepo                        = 0;
    uint8_t featureSelection                        = 0;
    uint8_t HWDTValue                               = 0;
    uint8_t AWDT1Value                              = 0;
    uint8_t AWDT2Value                              = 0;
    uint8_t acCryptoRequest                         = 0;
    uint8_t cryptoAPISupport = NX_CONF_CRYPTOAPI_ASYMMETRIC_DISABLED | NX_CONF_CRYPTOAPI_SYMMETRIC_DISABLED;
    uint8_t acChangeKey      = 0;
    Nx_slot_buffer_policy_t TBPolicy[NX_TB_POLICY_MAX_COUNT] = {0};
    uint8_t TBPolicyCount                                    = NX_TB_POLICY_MAX_COUNT;
    Nx_slot_buffer_policy_t SBPolicy[NX_SB_POLICY_MAX_COUNT] = {0};
    uint8_t SBPolicyCount                                    = NX_SB_POLICY_MAX_COUNT;
    uint32_t lockMap                                         = 0;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Running Get Configuration Example ex_sss_set_config.c");

    sm_status = nx_GetConfig_ManufactureConfig(&((sss_nx_session_t *)pSession)->s_ctx, &productFeature);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get Manufacture Features successful !!!");

    if (productFeature & NX_CONF_FEATURE_UNILATERAL_AUTH_ENABLED) {
        LOG_I(" Support ECC-based Unilateral Authentication: Enabled");
    }
    else {
        LOG_I(" Support ECC-based Unilateral Authentication: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_IMPORT_KEY_ENABLED) {
        LOG_I(" Support Import of ECC Private Key: Enabled");
    }
    else {
        LOG_I(" Support Import of ECC Private Key: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_DATA_1K_LIMIT_ENABLED) {
        LOG_I(" Enable Enforce User Data Files 1k Limit: Enabled");
    }
    else {
        LOG_I(" Enable Enforce User Data Files 1k Limit: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_COUNTER_ENABLED) {
        LOG_I(" Counter Support: Enabled");
    }
    else {
        LOG_I(" Counter Support: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_ECDSA_V4_ENABLED) {
        LOG_I(" EC DSA 4.0: Enabled");
    }
    else {
        LOG_I(" EC DSA 4.0: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_CCM_ENABLED) {
        LOG_I(" CCM AES-256 Secure Channel: Enabled");
    }
    else {
        LOG_I(" CCM AES-256 Secure Channel: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_EV2_AES256_ENABLED) {
        LOG_I(" NTAG AES-256 Secure Channel: Enabled");
    }
    else {
        LOG_I(" NTAG AES-256 Secure Channel: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_EV2_AES128_ENABLED) {
        LOG_I(" NTAG AES-128 Secure Channel: Enabled");
    }
    else {
        LOG_I(" NTAG AES-128 Secure Channel: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_CRYPTO_ECC_ENABLED) {
        LOG_I(" External Crypto API ECC Support: Enabled");
    }
    else {
        LOG_I(" External Crypto API ECC Support: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_CRYPTO_AES_ENABLED) {
        LOG_I(" External Crypto API AES Support: Enabled");
    }
    else {
        LOG_I(" External Crypto API AES Support: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_GPIO_ENABLED) {
        LOG_I(" GPIO Support: Enabled");
    }
    else {
        LOG_I(" GPIO Support: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_I2C_ENABLED) {
        LOG_I(" I2C IO Support: Enabled");
    }
    else {
        LOG_I(" I2C IO Support: Disabled");
    }
    if (productFeature & NX_CONF_FEATURE_NFC_ENABLED) {
        LOG_I(" NFC IO Support: Enabled");
    }
    else {
        LOG_I(" NFC IO Support: Disabled");
    }

    sm_status = nx_GetConfig_PICCConfig(&((sss_nx_session_t *)pSession)->s_ctx, &PICCConfig);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get PICC Configurations successful !!!");
    if (PICCConfig & NX_CONF_PICC_USERID) {
        LOG_I(" User RID (Random ISO ID): Enabled");
    }
    else {
        LOG_I(" User RID (Random ISO ID): Disabled");
    }

    sm_status = nx_GetConfig_ATSUpdate(&((sss_nx_session_t *)pSession)->s_ctx, userATS, &userATSLen);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get ATS Update Configurations successful !!!");
    LOG_MAU8_I(" User defined ATS:", userATS, userATSLen);

    sm_status = nx_GetConfig_SAKUpdate(&((sss_nx_session_t *)pSession)->s_ctx, &sak1, &sak2);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get SAK Update Configurations successful !!!");
    LOG_I(" User defined User defined SAK1: 0x%x", sak1);
    LOG_I(" User defined User defined SAK2: 0x%x", sak2);

    sm_status = nx_GetConfig_SMConfig(&((sss_nx_session_t *)pSession)->s_ctx, &SMConfigA, &SMConfigB);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get Secure messaging configuration successful !!!");
    if (SMConfigB & NX_CONF_SMCONFIG_DISABLE_CHAIN_WRITE) {
        LOG_I(" Chained writing: Disabled");
    }
    else {
        LOG_I(" Chained writing: Enabled");
    }

    sm_status = nx_GetConfig_CapData(&((sss_nx_session_t *)pSession)->s_ctx, &CapDataBuf[0], &CapDataBufLen);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    ENSURE_OR_GO_CLEANUP(CapDataBufLen == NX_CONF_CAPABILITY_DATA_LEN);
    LOG_I("=======================================");
    LOG_I("Get Capability Data successful !!!");
    LOG_I(" User configured PDCap2.5: 0x%x", CapDataBuf[NX_CONF_CAPABILITY_DATA_PDCAP2_5_INDEX]);
    LOG_I(" User configured PDCap2.6: 0x%x", CapDataBuf[NX_CONF_CAPABILITY_DATA_PDCAP2_6_INDEX]);

    sm_status = nx_GetConfig_ATQAUpdate(&((sss_nx_session_t *)pSession)->s_ctx, &userATQA);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get ATQA Update successful !!!");
    LOG_MAU8_I(" User defined ATQA:", (uint8_t *)(&userATQA), sizeof(userATQA));

    sm_status = nx_GetConfig_SilentModeConfig(&((sss_nx_session_t *)pSession)->s_ctx, &silentMode, &REQS, &WUPS);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get Silent Mode Configuration successful !!!");
    if (silentMode & NX_CONF_SILENTMODE_CUSTOMIZED_REQS_WUPS_ENABLE) {
        LOG_I(" Customized REQS/WUPS: Enabled");
        LOG_I(" Custom REQS: 0x%x", REQS);
        LOG_I(" Custom WUPS: 0x%x", WUPS);
    }
    else {
        LOG_I(" Customized REQS/WUPS: Disabled");
    }
    if (silentMode & NX_CONF_SILENTMODE_SILENT_ENABLE) {
        LOG_I(" Silent mode: Enabled");
    }
    else {
        LOG_I(" Silent mode: Disabled");
    }

    sm_status =
        nx_GetConfig_EnhancedPrivacyConfig(&((sss_nx_session_t *)pSession)->s_ctx, &privacyOption, &appPrivacyKey);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get Enhanced Privacy Configuration successful !!!");
    if (privacyOption & NX_CONF_PRIVACY_ORIGINALITY_DISABLED) {
        LOG_I(" Originality Check: Disabled");
    }
    else {
        LOG_I(" Originality Check: Enabled");
    }
    if (privacyOption & NX_CONF_PRIVACY_MANU_MASK_ENABLED) {
        LOG_I(" Manufacturer data masking: Enabled");
    }
    else {
        LOG_I(" Manufacturer data masking: Disabled");
    }
    if (privacyOption & NX_CONF_PRIVACY_APPPRIVACYKEY_ENABLED) {
        LOG_I(" KeyID.AppPrivacyKey: Enabled");
    }
    else {
        LOG_I(" KeyID.AppPrivacyKey: Disabled");
    }
    LOG_I(" KeyID.AppPrivacyKey definition: 0x%x", appPrivacyKey);

    sm_status = nx_GetConfig_NFCMgmt(&((sss_nx_session_t *)pSession)->s_ctx, &nfcSupport, &protocolOptions);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get NFC Management Configuration successful !!!");
    if (nfcSupport & NX_CONF_NFC_ENABLED) {
        LOG_I(" NFC I/O: Enabled");
    }
    else {
        LOG_I(" NFC I/O: Disabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SIGI_VERIFIER_ENABLED) {
        LOG_I(" SIGMA-I Verifier: Enabled");
    }
    else {
        LOG_I(" SIGMA-I Verifier: Disabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SIGI_PROVER_ENABLED) {
        LOG_I(" SIGMA-I Prover: Enabled");
    }
    else {
        LOG_I(" SIGMA-I Prover: Disabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SECURE_TUNNEL_NTAGEV2_SUPPORTED) {
        LOG_I(" NTAG EV2 secure messaging: Disabled");
    }
    else {
        LOG_I(" NTAG EV2 secure messaging: Enabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SECURE_TUNNEL_AES256_SUPPORTED) {
        LOG_I(" Secure Tunnel strength: AES-256 supported");
    }
    else {
        LOG_I(" Secure Tunnel strength: AES-256 not supported");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SECURE_TUNNEL_AES128_SUPPORTED) {
        LOG_I(" Secure Tunnel strength: AES-128 supported");
    }
    else {
        LOG_I(" Secure Tunnel strength: AES-128 not supported");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_CARD_UNILATERAL_ENABLED) {
        LOG_I(" ECC-based Card-Unilateral Authentication: Enabled");
    }
    else {
        LOG_I(" ECC-based Card-Unilateral Authentication: Disabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SYMM_AUTH_ENABLED) {
        LOG_I(" AES-based Symmetric Authentication: Enabled");
    }
    else {
        LOG_I(" AES-based Symmetric Authentication: Enabled");
    }

    sm_status = nx_GetConfig_I2CMgmt(&((sss_nx_session_t *)pSession)->s_ctx, &i2cSupport, &i2cAddr, &protocolOptions);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get I2C Management Configuration successful !!!");
    if (i2cSupport & NX_CONF_I2C_ENABLED) {
        LOG_I(" I2C I/O: Enabled");
    }
    else {
        LOG_I(" I2C I/O: Disabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SIGI_VERIFIER_ENABLED) {
        LOG_I(" SIGMA-I Verifier: Enabled");
    }
    else {
        LOG_I(" SIGMA-I Verifier: Disabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SIGI_PROVER_ENABLED) {
        LOG_I(" SIGMA-I Prover: Enabled");
    }
    else {
        LOG_I(" SIGMA-I Prover: Disabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SECURE_TUNNEL_NTAGEV2_SUPPORTED) {
        LOG_I(" NTAG EV2 secure messaging: Disabled");
    }
    else {
        LOG_I(" NTAG EV2 secure messaging: Enabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SECURE_TUNNEL_AES256_SUPPORTED) {
        LOG_I(" Secure Tunnel strength: AES-256 supported");
    }
    else {
        LOG_I(" Secure Tunnel strength: AES-256 not supported");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SECURE_TUNNEL_AES128_SUPPORTED) {
        LOG_I(" Secure Tunnel strength: AES-128 supported");
    }
    else {
        LOG_I(" Secure Tunnel strength: AES-128 not supported");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_CARD_UNILATERAL_ENABLED) {
        LOG_I(" ECC-based Card-Unilateral Authentication: Enabled");
    }
    else {
        LOG_I(" ECC-based Card-Unilateral Authentication: Disabled");
    }
    if (protocolOptions & NX_CONF_PROTOCOL_OPTIONS_SYMM_AUTH_ENABLED) {
        LOG_I(" AES-based Symmetric Authentication: Enabled");
    }
    else {
        LOG_I(" AES-based Symmetric Authentication: Enabled");
    }

    sm_status = nx_GetConfig_GPIOMgmt(&((sss_nx_session_t *)pSession)->s_ctx, &gpioConfig);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get GPIO Management Configuration successful !!!");

    switch (gpioConfig.gpio1Mode) {
    case Nx_GPIOMgmtCfg_GPIOMode_Disabled:
        LOG_I(" GPIO 1 Mode: Disabled");
        break;
    case Nx_GPIOMgmtCfg_GPIOMode_Input:
        LOG_I(" GPIO 1 Mode: Input");
        if (gpioConfig.gpio1DebounceFilterEnabled) {
            LOG_I("  GPIO 1 Debounce filter: Enabled");
            LOG_I("  GPIO 1 Debounce filter value: 0x%x", gpioConfig.gpio1DebounceFilterValue);
        }
        else {
            LOG_I("  GPIO 1 Debounce filter: Disabled");
        }
        switch (gpioConfig.gpio1InputFilterSelection) {
        case Nx_GPIOPadCfg_InputFilter_Unfiltered_50ns:
            LOG_I("GPIO 1 Input filter selection: filter of 50ns but has no effect");
            break;
        case Nx_GPIOPadCfg_InputFilter_Unfiltered_10ns:
            LOG_I("GPIO 1 Input filter selection: filter of 10ns but has no effect");
            break;
        case Nx_GPIOPadCfg_InputFilter_ZIFfiltered_50ns:
            LOG_I("GPIO 1 Input filter selection: ZIF filter of 50ns");
            break;
        case Nx_GPIOPadCfg_InputFilter_ZIFfiltered_10ns:
            LOG_I("GPIO 1 Input filter selection: ZIF filter of 10ns");
            break;
        default:
            break;
        }
        switch (gpioConfig.gpio1InputCfg) {
        case Nx_GPIOPadCfg_InputCfg_PlainInput_WeakPullUp:
            LOG_I("  GPIO 1 Plain input with weak pull-up");
            break;
        case Nx_GPIOPadCfg_InputCfg_PlainInput_Repeater:
            LOG_I("  GPIO 1 Plain input with repeater (bus keeper)");
            break;
        case Nx_GPIOPadCfg_InputCfg_PlainInput:
            LOG_I("  GPIO 1 Plain input");
            break;
        case Nx_GPIOPadCfg_InputCfg_PlainInput_WeakPullDown:
            LOG_I("  GPIO 1 Plain input with weak pull-down");
            break;
        case Nx_GPIOPadCfg_InputCfg_WeakPullUp:
            LOG_I("  GPIO 1 Weak pull-up");
            break;
        case Nx_GPIOPadCfg_InputCfg_WPDN:
            LOG_I("  GPIO 1 Weak pull-down (DISABLE_WPDN)");
            break;
        case Nx_GPIOPadCfg_InputCfg_HighImpedance:
            LOG_I("  GPIO 1 High impedance (analog I/O)");
            break;
        case Nx_GPIOPadCfg_InputCfg_WPD:
            LOG_I("  GPIO 1 Weak pull-down (DISABLE_WPD)");
            break;
        default:
            break;
        }
        break;
    case Nx_GPIOMgmtCfg_GPIOMode_Output:
        LOG_I(" GPIO 1 Mode: Output");
        if (gpioConfig.gpio1OutputInitStateHigh) {
            LOG_I("  GPIO 1 Initial state after power cycle: High");
        }
        else {
            LOG_I("  GPIO 1 Initial state after power cycle: Low");
        }
        switch (gpioConfig.gpio1OutputCfg) {
        case Nx_GPIOPadCfg_OutputCfg_I2C_SF_FP_Tx_HS_Tx:
            LOG_I("  GPIO 1 Output config: I2C S/F and FP transmit mode");
            break;
        case Nx_GPIOPadCfg_OutputCfg_I2C_HS_Tx:
            LOG_I("  GPIO 1 Output config: I2C HS transmit mode (only SCLK)");
            break;
        case Nx_GPIOPadCfg_OutputCfg_I2C_TX_SFFP:
            LOG_I("  GPIO 1 Output config: I2C_T X_SF F P");
            break;
        case Nx_GPIOPadCfg_OutputCfg_I2C_TX_HS_SCLK:
            LOG_I("  GPIO 1 Output config: I2C_T X_HS_SCLK");
            break;
        case Nx_GPIOPadCfg_OutputCfg_GPIO_Low_Speed_1:
            LOG_I("  GPIO 1 Output config:  GPIO Low speed mode (GPIO_LOW_SPEED_1)");
            break;
        case Nx_GPIOPadCfg_OutputCfg_GPIO_Low_Speed_2:
            LOG_I("  GPIO 1 Output config: GPIO Low speed mode (GPIO_LOW_SPEED_2)");
            break;
        case Nx_GPIOPadCfg_OutputCfg_GPIO_High_Speed_1:
            LOG_I("  GPIO 1 Output config: GPIO High speed mode (GPIO_HIGH_SPEED_1)");
            break;
        case Nx_GPIOPadCfg_OutputCfg_GPIO_High_Speed_2:
            LOG_I("  GPIO 1 Output config: GPIO High speed mode (GPIO_HIGH_SPEED_2)");
            break;
        default:
            break;
        }
        switch (gpioConfig.gpio1OutputNotif) {
        case Nx_GPIOMgmtCfg_GPIONotif_Disabled:
            LOG_I(" GPIO 1 notification on authentication: Disabled");
            break;
        case Nx_GPIOMgmtCfg_GPIONotif_Auth:
            LOG_I(" GPIO 1 notification on authentication: Enabled");
            break;
        case Nx_GPIOMgmtCfg_GPIONotif_NFC:
            LOG_I(" GPIO 1 notification on authentication: Enabled on NFC field");
            break;
        default:
            break;
        }
        break;
    case Nx_GPIOMgmtCfg_GPIOMode_InputTagTamper:
        LOG_I(" GPIO 1 Mode: Input Tag Tamper");
        break;
    case Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut:
        LOG_I(" GPIO 1 Mode: Down-stream Power Out");
        if (gpioConfig.gpio1PowerOutI2CEnabled) {
            LOG_I("  GPIO 1 I2C support: Enabled");
        }
        else {
            LOG_I("  GPIO 1 I2C support: Disabled");
        }
        if (gpioConfig.gpio1PowerOutBackpowerEnabled) {
            LOG_I("  GPIO 1 Backpower: Enabled");
        }
        else {
            LOG_I("  GPIO 1 Backpower: Disabled");
        }
        switch (gpioConfig.gpio1PowerOutDefaultTarget) {
        case Nx_GPIOPowerOut_1800mV_100uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 100uA");
            break;
        case Nx_GPIOPowerOut_1800mV_300uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 300uA");
            break;
        case Nx_GPIOPowerOut_1800mV_500uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 500uA");
            break;
        case Nx_GPIOPowerOut_1800mV_1000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 1mA");
            break;
        case Nx_GPIOPowerOut_1800mV_2000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 2mA");
            break;
        case Nx_GPIOPowerOut_1800mV_3000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 3mA");
            break;
        case Nx_GPIOPowerOut_1800mV_5000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 5mA");
            break;
        case Nx_GPIOPowerOut_1800mV_7000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 7mA");
            break;
        case Nx_GPIOPowerOut_1800mV_10000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 1.8V and current of 10mA");
            break;
        case Nx_GPIOPowerOut_2000mV_100uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 100uA");
            break;
        case Nx_GPIOPowerOut_2000mV_300uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 300uA");
            break;
        case Nx_GPIOPowerOut_2000mV_500uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 500uA");
            break;
        case Nx_GPIOPowerOut_2000mV_1000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 1mA");
            break;
        case Nx_GPIOPowerOut_2000mV_2000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 2mA");
            break;
        case Nx_GPIOPowerOut_2000mV_3000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 3mA");
            break;
        case Nx_GPIOPowerOut_2000mV_5000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 5mA");
            break;
        case Nx_GPIOPowerOut_2000mV_7000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 7mA");
            break;
        case Nx_GPIOPowerOut_2000mV_10000uA:
            LOG_I("  GPIO 1 DefaultTarget: power downstream voltage of 2V and current of 10mA");
            break;
        default:
            break;
        }
        switch (gpioConfig.gpio1PowerOutInRushTarget) {
        case Nx_GPIOPowerOut_1800mV_100uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 100uA");
            break;
        case Nx_GPIOPowerOut_1800mV_300uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 300uA");
            break;
        case Nx_GPIOPowerOut_1800mV_500uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 500uA");
            break;
        case Nx_GPIOPowerOut_1800mV_1000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 1mA");
            break;
        case Nx_GPIOPowerOut_1800mV_2000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 2mA");
            break;
        case Nx_GPIOPowerOut_1800mV_3000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 3mA");
            break;
        case Nx_GPIOPowerOut_1800mV_5000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 5mA");
            break;
        case Nx_GPIOPowerOut_1800mV_7000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 7mA");
            break;
        case Nx_GPIOPowerOut_1800mV_10000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 1.8V and current of 10mA");
            break;
        case Nx_GPIOPowerOut_2000mV_100uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 100uA");
            break;
        case Nx_GPIOPowerOut_2000mV_300uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 300uA");
            break;
        case Nx_GPIOPowerOut_2000mV_500uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 500uA");
            break;
        case Nx_GPIOPowerOut_2000mV_1000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 1mA");
            break;
        case Nx_GPIOPowerOut_2000mV_2000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 2mA");
            break;
        case Nx_GPIOPowerOut_2000mV_3000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 3mA");
            break;
        case Nx_GPIOPowerOut_2000mV_5000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 5mA");
            break;
        case Nx_GPIOPowerOut_2000mV_7000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 7mA");
            break;
        case Nx_GPIOPowerOut_2000mV_10000uA:
            LOG_I("  GPIO 1 InRushTarget: power downstream voltage of 2V and current of 10mA");
            break;
        default:
            break;
        }
        LOG_I(" GPIO 1 duration to apply InRushTarget: %x", gpioConfig.gpio1PowerOutInRushDuration);
        LOG_I(" GPIO 1 additional current for power harvesting: %x", gpioConfig.gpio1PowerOutAdditionalCurrent);
        break;
    default:
        break;
    }

    if (gpioConfig.gpio1Supply1v1n1v2) {
        LOG_I("  GPIO 1 supply selection: 1V8 signaling in I2C mode");
    }
    else {
        LOG_I("  GPIO 1 supply selection: 1V1 and 1V2 signaling in I2c mode");
    }

    switch (gpioConfig.gpio2Mode) {
    case Nx_GPIOMgmtCfg_GPIOMode_Disabled:
        LOG_I(" GPIO 2 Mode: Disabled");
        break;
    case Nx_GPIOMgmtCfg_GPIOMode_Input:
        LOG_I(" GPIO 2 Mode: Input");
        if (gpioConfig.gpio2DebounceFilterEnabled) {
            LOG_I("  GPIO 2 Debounce filter: Enabled");
            LOG_I("  GPIO 2 Debounce filter value: 0x%x", gpioConfig.gpio2DebounceFilterValue);
        }
        else {
            LOG_I("  GPIO 2 Debounce filter: Disabled");
        }
        switch (gpioConfig.gpio2InputFilterSelection) {
        case Nx_GPIOPadCfg_InputFilter_Unfiltered_50ns:
            LOG_I("GPIO 2 Input filter selection: filter of 50ns but has no effect");
            break;
        case Nx_GPIOPadCfg_InputFilter_Unfiltered_10ns:
            LOG_I("GPIO 2 Input filter selection: filter of 10ns but has no effect");
            break;
        case Nx_GPIOPadCfg_InputFilter_ZIFfiltered_50ns:
            LOG_I("GPIO 2 Input filter selection: ZIF filter of 50ns");
            break;
        case Nx_GPIOPadCfg_InputFilter_ZIFfiltered_10ns:
            LOG_I("GPIO 2 Input filter selection: ZIF filter of 10ns");
            break;
        default:
            break;
        }
        switch (gpioConfig.gpio2InputCfg) {
        case Nx_GPIOPadCfg_InputCfg_PlainInput_WeakPullUp:
            LOG_I("  GPIO 2 Plain input with weak pull-up");
            break;
        case Nx_GPIOPadCfg_InputCfg_PlainInput_Repeater:
            LOG_I("  GPIO 2 Plain input with repeater (bus keeper)");
            break;
        case Nx_GPIOPadCfg_InputCfg_PlainInput:
            LOG_I("  GPIO 2 Plain input");
            break;
        case Nx_GPIOPadCfg_InputCfg_PlainInput_WeakPullDown:
            LOG_I("  GPIO 2 Plain input with weak pull-down");
            break;
        case Nx_GPIOPadCfg_InputCfg_WeakPullUp:
            LOG_I("  GPIO 2 Weak pull-up");
            break;
        case Nx_GPIOPadCfg_InputCfg_WPDN:
            LOG_I("  GPIO 2 Weak pull-down (DISABLE_WPDN)");
            break;
        case Nx_GPIOPadCfg_InputCfg_HighImpedance:
            LOG_I("  GPIO 2 High impedance (analog I/O)");
            break;
        case Nx_GPIOPadCfg_InputCfg_WPD:
            LOG_I("  GPIO 2 Weak pull-down (DISABLE_WPD)");
            break;
        default:
            break;
        }
        break;
    case Nx_GPIOMgmtCfg_GPIOMode_Output:
        LOG_I(" GPIO 2 Mode: Output");
        if (gpioConfig.gpio2OutputInitStateHigh) {
            LOG_I("  GPIO 2 Initial state after power cycle: High");
        }
        else {
            LOG_I("  GPIO 2 Initial state after power cycle: Low");
        }
        switch (gpioConfig.gpio2OutputCfg) {
        case Nx_GPIOPadCfg_OutputCfg_I2C_SF_FP_Tx_HS_Tx:
            LOG_I("  GPIO 2 Output config: I2C S/F and FP transmit mode");
            break;
        case Nx_GPIOPadCfg_OutputCfg_I2C_HS_Tx:
            LOG_I("  GPIO 2 Output config: I2C HS transmit mode (only SCLK)");
            break;
        case Nx_GPIOPadCfg_OutputCfg_I2C_TX_SFFP:
            LOG_I("  GPIO 2 Output config: I2C_T X_SF F P");
            break;
        case Nx_GPIOPadCfg_OutputCfg_I2C_TX_HS_SCLK:
            LOG_I("  GPIO 2 Output config: I2C_T X_HS_SCLK");
            break;
        case Nx_GPIOPadCfg_OutputCfg_GPIO_Low_Speed_1:
            LOG_I("  GPIO 2 Output config:  GPIO Low speed mode (GPIO_LOW_SPEED_1)");
            break;
        case Nx_GPIOPadCfg_OutputCfg_GPIO_Low_Speed_2:
            LOG_I("  GPIO 2 Output config: GPIO Low speed mode (GPIO_LOW_SPEED_2)");
            break;
        case Nx_GPIOPadCfg_OutputCfg_GPIO_High_Speed_1:
            LOG_I("  GPIO 2 Output config: GPIO High speed mode (GPIO_HIGH_SPEED_1)");
            break;
        case Nx_GPIOPadCfg_OutputCfg_GPIO_High_Speed_2:
            LOG_I("  GPIO 2 Output config: GPIO High speed mode (GPIO_HIGH_SPEED_2)");
            break;
        default:
            break;
        }
        switch (gpioConfig.gpio2OutputNotif) {
        case Nx_GPIOMgmtCfg_GPIONotif_Disabled:
            LOG_I(" GPIO 2 notification on authentication: Disabled");
            break;
        case Nx_GPIOMgmtCfg_GPIONotif_Auth:
            LOG_I(" GPIO 2 notification on authentication: Enabled");
            break;
        case Nx_GPIOMgmtCfg_GPIONotif_NFC:
            LOG_I(" GPIO 2 notification on authentication: Enabled on NFC field");
            break;
        default:
            break;
        }
        break;
    case Nx_GPIOMgmtCfg_GPIOMode_NfcPausefileOut:
        LOG_I("GPIO 2 Output NFC Pause FileNo: %x", gpioConfig.gpio2OutputNFCPauseFileNo);
        LOG_I("GPIO 2 Output NFC Pause Offset: %x", gpioConfig.gpio2OutputNFCPauseOffset);
        LOG_I("GPIO 2 Output NFC Pause Length: %x", gpioConfig.gpio2OutputNFCPauseLength);
    default:
        break;
    }

    if (gpioConfig.gpio2Supply1v1n1v2) {
        LOG_I("  GPIO 2 supply selection: 1V8 signaling in I2C mode");
    }
    else {
        LOG_I("  GPIO 2 supply selection: 1V1 and 1V2 signaling in I2c mode");
    }

    switch ((gpioConfig.acManage & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) {
    case Nx_CommMode_Plain:
        LOG_I(" Cmd.ManageGPIO communication modes: No protection.");
        break;
    case Nx_CommMode_MAC:
        LOG_I(" Cmd.ManageGPIO communication modes: MAC protection.");
        break;
    case Nx_CommMode_FULL:
        LOG_I(" Cmd.ManageGPIO communication modes: Full protection.");
        break;
    default:
        break;
    }
    LOG_I(" Cmd.ManageGPIO access condition 0x%x", gpioConfig.acManage);

    switch ((gpioConfig.acRead & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) {
    case Nx_CommMode_Plain:
        LOG_I(" Cmd.ReadGPIO communication modes: No protection.");
        break;
    case Nx_CommMode_MAC:
        LOG_I(" Cmd.ReadGPIO communication modes: MAC protection.");
        break;
    case Nx_CommMode_FULL:
        LOG_I(" Cmd.ReadGPIO communication modes: Full protection.");
        break;
    default:
        break;
    }
    LOG_I(" Cmd.ReadGPIO access condition 0x%x", gpioConfig.acRead);

    sm_status = nx_GetConfig_EccKeyMgmt(&((sss_nx_session_t *)pSession)->s_ctx, &keyAC, &rootKeyAC);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get ECC Key Management Configuration successful !!!");

    switch ((keyAC & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) {
    case Nx_CommMode_Plain:
        LOG_I(" Cmd.ManageKeyPair communication modes: No protection.");
        break;
    case Nx_CommMode_MAC:
        LOG_I(" Cmd.ManageKeyPair communication modes: MAC protection.");
        break;
    case Nx_CommMode_FULL:
        LOG_I(" Cmd.ManageKeyPair communication modes: Full protection.");
        break;
    default:
        break;
    }
    LOG_I(" Cmd.ManageKeyPair access condition 0x%x", keyAC & NX_CONF_AC_MASK);
    switch ((rootKeyAC & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) {
    case Nx_CommMode_Plain:
        LOG_I(" Cmd.ManageCARootKey communication modes: No protection.");
        break;
    case Nx_CommMode_MAC:
        LOG_I(" Cmd.ManageCARootKey communication modes: MAC protection.");
        break;
    case Nx_CommMode_FULL:
        LOG_I(" Cmd.ManageCARootKey communication modes: Full protection.");
        break;
    default:
        break;
    }
    LOG_I(" Cmd.ManageCARootKey access condition 0x%x", rootKeyAC & NX_CONF_COMM_MODE_MASK);

    sm_status = nx_GetConfig_CertMgmt(
        &((sss_nx_session_t *)pSession)->s_ctx, &leafCacheSize, &intermCacheSize, &featureSelection, &acManageCertRepo);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get Certificate Management Configuration successful !!!");

    LOG_I(" End Leaf certificate cache size: 0x%x", leafCacheSize);
    LOG_I(" Intermediate certificate cache size: 0x%x", intermCacheSize);
    if (featureSelection & NX_CONF_CERT_SIGMA_I_CACHE_ENABLED) {
        LOG_I("  SIGMA-I Cache: Enabled");
    }
    else {
        LOG_I("  SIGMA-I Cache: Disabled");
    }
    switch ((acManageCertRepo & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) {
    case sss_CommMode_Plain:
        LOG_I(" Cmd.ManageCertRepo communication modes: No protection.");
        break;
    case sss_CommMode_MAC:
        LOG_I(" Cmd.ManageCertRepo communication modes: MAC protection.");
        break;
    case sss_CommMode_FULL:
        LOG_I(" Cmd.ManageCertRepo communication modes: Full protection.");
        break;
    default:
        break;
    }
    LOG_I(" Cmd.ManageCertRepo access condition 0x%x", acManageCertRepo & NX_CONF_AC_MASK);

    sm_status =
        nx_GetConfig_WatchdogTimerMgmt(&((sss_nx_session_t *)pSession)->s_ctx, &HWDTValue, &AWDT1Value, &AWDT2Value);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get Watchdog Timer Management Configuration successful !!!");

    LOG_I(" Halt Watchdog Timer (HWDT) Value: 0x%x", HWDTValue);
    LOG_I(" Authorization Watch-Dog Timer (AWDT1) Value: 0x%x", AWDT1Value);
    LOG_I(" Authorization Watch-Dog Timer (AWDT2) Value: 0x%x", AWDT2Value);

    sm_status = nx_GetConfig_CryptoAPIMgmt(&((sss_nx_session_t *)pSession)->s_ctx,
        &cryptoAPISupport,
        &acCryptoRequest, // CommMode Access Condition Value for Cmd.CryptoRequest
        &acChangeKey,     // Access condition for Cmd.ChangeKey targeting KeyID.CryptoRequestKey.
        &TBPolicyCount,
        TBPolicy,
        &SBPolicyCount,
        SBPolicy);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get Crypto API Management Configuration successful !!!");
    if (cryptoAPISupport & NX_CONF_CRYPTOAPI_ASYMMETRIC_ENABLED) {
        LOG_I(" Asymmetric Crypto API: Enabled");
    }
    else {
        LOG_I(" Asymmetric Crypto API: Disabled");
    }
    if (cryptoAPISupport & NX_CONF_CRYPTOAPI_SYMMETRIC_ENABLED) {
        LOG_I(" Symmetric Crypto API: Enabled");
    }
    else {
        LOG_I(" Symmetric Crypto API: Disabled");
    }
    switch ((acCryptoRequest & NX_CONF_COMM_MODE_MASK) >> NX_COMM_MODE_BIT_SHIFT) {
    case Nx_CommMode_Plain:
        LOG_I(" Cmd.CryptoRequest communication modes: No protection.");
        break;
    case Nx_CommMode_MAC:
        LOG_I(" Cmd.CryptoRequest communication modes: MAC protection.");
        break;
    case Nx_CommMode_FULL:
        LOG_I(" Cmd.CryptoRequest communication modes: Full protection.");
        break;
    default:
        break;
    }
    LOG_I(" Cmd.CryptoRequest access condition 0x%x", acCryptoRequest & NX_CONF_AC_MASK);
    LOG_I(" Cmd.CryptoRequest access condition for ChangeKey command targeting CryptoRequest Keys 0x%x", acChangeKey);
    LOG_MAU8_I("Crypto API TB Policy:", (uint8_t *)TBPolicy, (TBPolicyCount * NX_POLICY_BUF_SIZE));
    LOG_MAU8_I("Crypto API SB Policy:", (uint8_t *)SBPolicy, (SBPolicyCount * NX_POLICY_BUF_SIZE));

    sm_status = nx_GetConfig_LockConfig(&((sss_nx_session_t *)pSession)->s_ctx, &lockMap);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
    LOG_I("=======================================");
    LOG_I("Get Lock Configuration successful !!!");

    LOG_I(" Lock bitmap: %x", lockMap);

cleanup:
    if (SM_OK == sm_status) {
        status = kStatus_SSS_Success;
        LOG_I("ex_sss_get_config Example Success !!!...");
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("ex_sss_get_config Example Failed !!!...");
    }

    return status;
}
