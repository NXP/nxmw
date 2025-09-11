/*
 *
 * Copyright 2019-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file */

#ifndef NX_APDU_H
#define NX_APDU_H

#include "nx_apdu_tlv.h"

/**
 * @file nx_apdu.h
 * @brief APDU interface for secure authenticator communication.
 */

/** @brief Halt/Wake-up configuration
 *
 */
typedef struct
{
    /** wake up from HALT state on presence of NFC field. */
    uint8_t nfcWakeup : 1;
    /** I2C wake-up address */
    uint8_t i2cWakeupAddress;
    /** I2C SDA wake-up cycles */
    uint8_t i2cWakeupCycle;
    /** GPIO wake-up, GPIO2 pull-down will trigger wake-up. */
    uint8_t gpioWakeup : 1;
    /** I2C address wake-up. */
    uint8_t i2cAddressWakeup : 1;
    /** I2C SDA cycle wake-up */
    uint8_t i2cCycleWakeup : 1;
    /** RDAC Setting */
    uint8_t RDACSetting;
    /** Before entering HALT state, GPIO pins will reset to their PoR state. */
    uint8_t gpioReset : 1;
} nx_config_halt_wakeup_t;

/** @brief Deferred configuration options
 *
 */
typedef struct
{
    /** If this item is valid */
    uint8_t valid : 1;
    /** Deferral Method */
    uint8_t method;
} nx_config_deferred_option_t;

/** @brief All deferred configurations
 *
 */
typedef struct
{
    /** PICC Random ID Configuration */
    nx_config_deferred_option_t piccRndIdConfig;
    /** Silent Mode Configuration */
    nx_config_deferred_option_t silentModeConfig;
    /** GPIO Configuration */
    nx_config_deferred_option_t gpioConfig;
} nx_config_deferral_t;

/** @brief Activate configurations
 *
 */
typedef struct
{
    /** activate SetConfiguration 0x01 (RandomID) */
    uint8_t randomID : 1;
    /** activate SetConfiguration 0x0D (Silent Mode) */
    uint8_t silentMode : 1;
    /** TagTamper boot measurements */
    uint8_t tagTamperBoot : 1;
    /** activate ChangeFileSettings SDM encryptions */
    uint8_t changeFileSetting : 1;
} nx_activate_config_t;

/** @brief File access parameters
 *
 */
typedef struct nx_file_access_param_t
{
    /** File communication mode */
    Nx_CommMode_t commMode;
    /** File read access condition */
    Nx_AccessCondition_t readAccessCondition;
    /** File write access condition */
    Nx_AccessCondition_t writeAccessCondition;
    /** File read-write access condition */
    Nx_AccessCondition_t readWriteAccessCondition;
    /** File change access condition */
    Nx_AccessCondition_t changeAccessCondition;
} nx_file_access_param_t;

/** @brief File SDM configuration
 *
 */
typedef struct
{
    /** SDM options */
    uint8_t sdmOption;
    /** Access condition SDM Meta Read */
    uint8_t acSDMMetaRead;
    /** Access condition SDM File Read */
    uint8_t acSDMFileRead;
    /** Access condition SDM File Read 2 */
    uint8_t acSDMFileRead2;
    /** Access SDM counter return */
    uint8_t acSDMCtrRet;
    /** VCUID offset */
    uint32_t VCUIDOffset;
    /** SDM Read counter offset */
    uint32_t SDMReadCtrOffset;
    /** PICC Data Offset */
    uint32_t PICCDataOffset;
    /** GPIO Status Offset */
    uint32_t GPIOStatusOffset;
    /** SDMMAC Input Offset */
    uint32_t SDMMACInputOffset;
    /** SDMEN COffset */
    uint32_t SDMENCOffset;
    /** SDMENC Length */
    uint32_t SDMENCLength;
    /** SDMMAC Offset */
    uint32_t SDMMACOffset;
    /** SDM Read Counter Limit */
    uint32_t SDMReadCtrLimit;
    /** Defer SDMEnc enabled */
    bool deferSDMEncEnabled;
    /** SDM defer method */
    uint8_t sdmDeferMethod;
} nx_file_SDM_config_t;

/** @brief Crypto Key meta data parameters
 *
 */
typedef struct
{
    /** Key ID */
    uint8_t keyId;
    /** Key type */
    uint8_t keyType;
    /** Key policy */
    uint16_t keyPolicy;
} nx_crypto_key_meta_data_t;

/** @brief ECC ey meta data parameters
 *
 */
typedef struct
{
    /** Key ID */
    uint8_t keyId;
    /** Curve ID */
    uint8_t curveId;
    /** Key policy */
    uint16_t keyPolicy;
    /** Write Communication Mode */
    uint8_t writeCommMode;
    /** Write Access Condition */
    uint8_t writeAccessCond;
    /** KUC (Key Usage Counter) Limit */
    uint32_t kucLimit;
    /** Key Usage Counter */
    uint32_t keyUsageCtr;
} nx_ecc_key_meta_data_t;

/** @brief CA Root Key meta data parameters
 *
 */
typedef struct
{
    /** Key ID */
    uint8_t keyId;
    /** Curve ID */
    uint8_t curveId;
    /** AC Bitmap */
    uint16_t acBitmap;
    /** Write Communication Mode */
    uint8_t writeCommMode;
    /** Write Access Condition */
    uint8_t writeAccessCond;
} nx_ca_root_key_meta_data_t;

#ifdef __cplusplus
extern "C" {
#endif

/** nx_session_bind
 * @brief               Binds command counter, TI and auth status of one session context to another.
 *
 * @param[in]   pSession     Session context of session 1.
 * @param[in]   pConnectCtx2 Session context of session 2.
 *
 */
void nx_session_bind(SeSession_t *pSession, nx_connect_ctx_t *pConnectCtx2);

/** nx_session_unbind
 * @brief               Unbind a session. It will clear the conn_ctx pointer which is shared with other session.
 *
 * @param[in]   pSession     Session context of session.
 *
 */
void nx_session_unbind(SeSession_t *pSession);

/** nx_FreeMem
 * @brief               Gets the amount of free memory.
 *
 * @param[in]   session_ctx     Session context.
 * @param[out]  freeMemSize     Returned free memory size.
 *
 * @return  status
 */
smStatus_t nx_FreeMem(pSeSession_t session_ctx, uint32_t *freeMemSize);

/** nx_GetCardUID
 * @brief   Gets Card UID.
 *
 * @param[in]   session_ctx        Session context.
 * @param[out]  pGetCardUID        Pointer to the buffer containing the Card UID value.
 * @param[out]  getCardUIDLen      Length of the buffer containing the Card UID value.
 *
 * @return  status
*/
smStatus_t nx_GetCardUID(pSeSession_t session_ctx, uint8_t *pGetCardUID, size_t *getCardUIDLen);
/** nx_GetVersion
 * @brief   Gets Card Version Info.
 *
 * @param[in]   session_ctx    Session context.
 * @param[in]   getFabID       Whether or not to receive the Fab Identifier in the output.
 * @param[out]  pVersionInfo   Pointer to a structure containing version info.
 *
 * @return  status
*/
smStatus_t nx_GetVersion(pSeSession_t session_ctx, bool getFabID, Nx_VersionParams_t *pVersionInfo);
/** nx_Activate_Config
 * @brief   Command to activate deferred configuration.
 *
 * @param[in]   session_ctx   Session context.
 * @param[in]   configList    Buffer containing list of configurations to be activated.
 *
 * @return  status
*/
smStatus_t nx_Activate_Config(pSeSession_t session_ctx, nx_activate_config_t *configList);

/** nx_ManageCARootKey
 * @brief                  Manages various operations related to CARootKey like changing access conditions/communication mode etc..
 *
 * @param[in] session_ctx      Session context.
 * @param[in] objectID         Key number of the key to be managed.
 * @param[in] curveID          Targeted curve ID.
 * @param[in] acBitmap         Access rights associated with CARootKey.
 * @param[in] writeCommMode    Communication Mode required to update the key with this command.
 * @param[in] writeAccessCond  Access right required to update the key with this command.
 * @param[in] pubKey           Public Key.
 * @param[in] pubKeyLen        Public Key Length.
 * @param[in] caIssuerName     CA Issuer Name.
 * @param[in] caIssuerNameLen  CA Issuer Name Length.
 * @param[in] userCommMode     Communication Mode set by the user.
 *
 * @return  status
*/
smStatus_t nx_ManageCARootKey(pSeSession_t session_ctx,
    uint8_t objectID,
    uint8_t curveID,
    uint16_t acBitmap,
    Nx_CommMode_t writeCommMode,
    uint8_t writeAccessCond,
    const uint8_t *pubKey,
    size_t pubKeyLen,
    const uint8_t *caIssuerName,
    uint8_t caIssuerNameLen,
    Nx_CommMode_t userCommMode);

/** nx_ManageKeyPair
 * @brief Manages various operations related to ECC Private Keys like changing access conditions/communication mode etc..
 *
 * @param[in]   session_ctx       Session context.
 * @param[in]   objectID          Key number of the key to be managed.
 * @param[in]   option            Targeted action.
 * @param[in]   curveID           Targeted curve ID.
 * @param[in]   policy            Key policy of the targeted key (defines the allowed crypto operations with the targeted key).
 * @param[in]   kucLimit          Key Usage Counter Limit.
 * @param[in]   writeCommMode     Communication Mode required to update the key with this command.
 * @param[in]   writeAccessCond   Access right required to update the key with this command.
 * @param[in]   privateKey        Private Key.
 * @param[in]   privateKeyLen     Private Key Length.
 * @param[out]  pubKey            Public Key.
 * @param[out]  pubKeyLen         Public Key Length.
 * @param[in]   knownCommMode     Communication Mode set by the user.
 *
 * @return  status
*/

smStatus_t nx_ManageKeyPair(pSeSession_t session_ctx,
    uint8_t objectID,
    Nx_MgtKeyPair_Act_t option,
    Nx_ECCurve_t curveID,
    uint16_t policy,
    Nx_CommMode_t writeCommMode,
    uint8_t writeAccessCond,
    uint32_t kucLimit,
    const uint8_t *privateKey,
    size_t privateKeyLen,
    uint8_t *pubKey,
    size_t *pubKeyLen,
    Nx_CommMode_t knownCommMode);

/** nx_SetConfig_EccKeyMgmt
 * @brief Updates the configurations for ECC Key Management Operations
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   acManageKeyPair          Access Condition for the ManageKeyPair operation.
 * @param[in]   acManageCARootKey        Access Condition for the ManageCARootKey operation.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_EccKeyMgmt(pSeSession_t session_ctx, uint8_t acManageKeyPair, uint8_t acManageCARootKey);

/** nx_SetConfig_PICCConfig
 * @brief Updates the PICC Configurations.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   PICCConfig               Byte containing the PICC configurations that need to be set.
 *
 * @return  status
 */
smStatus_t nx_SetConfig_PICCConfig(pSeSession_t session_ctx, uint8_t PICCConfig);

/** nx_SetConfig_ATSUpdate
 * @brief   Updates the ATS configurations.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   userATS                  Buffer containing the user defined ATS configurations.
 * @param[in]   userATSLen               Buffer containing the user defined ATS configurations.
 *
 * @return  status
 */
smStatus_t nx_SetConfig_ATSUpdate(pSeSession_t session_ctx, uint8_t *userATS, size_t userATSLen);

/** nx_SetConfig_SAKUpdate
 * @brief Updates the SAK value.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   sak1                     SAK byte 1 to be updated.
 * @param[in]   sak2                     SAK byte 2 to be updated.
 *
 * @return  status
 */
smStatus_t nx_SetConfig_SAKUpdate(pSeSession_t session_ctx, uint8_t sak1, uint8_t sak2);

/** nx_SetConfig_SMConfig
 * @brief Updates the Secure Messaging Configuration.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   SMConfigA                containing Secure Messaging Configuration RFU.
 * @param[in]   SMConfigB                containing EV2 secure messaging configuration.
 *
 * @return  status
 */
smStatus_t nx_SetConfig_SMConfig(pSeSession_t session_ctx, uint8_t SMConfigA, uint8_t SMConfigB);

/** nx_SetConfig_CapData
 * @brief Update the PD Capability Data.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   CapDataBuf               Capability data Buffer, consisting of 10 bytes: PDCap1 5th byte and PDCap2 6th byte
 * @param[in]   CapDataBufLen            Capability data Length, consisting of length Capability data Buffer
 *
 * @return  status
 */
smStatus_t nx_SetConfig_CapData(pSeSession_t session_ctx, uint8_t *CapDataBuf, uint8_t CapDataBufLen);

/** nx_SetConfig_ATQAUpdate
 * @brief Update the ATQA value of the PICC card.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   userATQA                 Double byte containing user defined ATQA value.
 *
 * @return  status
 */
smStatus_t nx_SetConfig_ATQAUpdate(pSeSession_t session_ctx, uint16_t userATQA);

/** nx_SetConfig_SilentModeConfig
 * @brief Update the Silent Mode Configurations.
 *
 * @param[in]   session_ctx         Session context.
 * @param[in]   silentMode          Byte containing Silent Mode configurations.
 * @param[in]   REQS                [optional] Custom REQS, if silentMode[1] is true.
 * @param[in]   WUPS                [optional] Custom WUPS, if silentMode[1] is true.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_SilentModeConfig(pSeSession_t session_ctx, uint8_t silentMode, uint8_t REQS, uint8_t WUPS);

/** nx_SetConfig_EnhancedPrivacyConfig
 * @brief Updates Enhanced Privacy Configuration.
 *
 * @param[in]   session_ctx                 Session context.
 * @param[in]   privacyOption               Privacy Option Byte.
 * @param[in]   appPrivacyKey               AppPrivacyKey definition.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_EnhancedPrivacyConfig(pSeSession_t session_ctx, uint8_t privacyOption, uint8_t appPrivacyKey);

/** nx_SetConfig_NFCMgmt
 * @brief  Updates NFC Management Configurations.
 *
 * @param[in]   session_ctx          Session context.
 * @param[in]   nfcSupport           Byte containing NFC Support configuration.
 * @param[in]   protocolOptions      Two-byte map containing the crypto protocols supported over NFC.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_NFCMgmt(pSeSession_t session_ctx, uint8_t nfcSupport, uint16_t protocolOptions);

/** nx_SetConfig_I2CMgmt
 * @brief Updates I2C Management Configurations.
 *
 * @param[in]   session_ctx          Session context.
 * @param[in]   i2cSupport           Bit 1-7 RFU, Bit 0 enable/disable I2C I/O support.
 * @param[in]   i2cAddr              The address used for I2C target.
 * @param[in]   protocolOptions      Crypto protocols supported over I2C.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_I2CMgmt(
    pSeSession_t session_ctx, uint8_t i2cSupport, uint8_t i2cAddr, uint16_t protocolOptions);

/** nx_SetConfig_GPIOMgmt
 * @brief Updates the GPIO Management configurations.
 *
 * @param[in]   session_ctx          Session context.
 * @param[in]   gpioConfig           Structure containing all the GPIO related configurations.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_GPIOMgmt(pSeSession_t session_ctx, Nx_gpio_config_t gpioConfig);

/** nx_SetConfig_CertMgmt
 * @brief Updates Certificate Management Configurations.
 *
 * @param[in]   session_ctx             Session context.
 * @param[in]   leafCacheSize           End leaf certificate cache size.
 * @param[in]   intermCacheSize         Intermediate certificate cache size.
 * @param[in]   featureSelection        Feature Selection, Host Certificate Support, Internal Certificate Support and enable/disable SIGMA-I cache.
 * @param[in]   acManageCertRepo        Access Conditions to manage certificate repository access.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_CertMgmt(pSeSession_t session_ctx,
    uint8_t leafCacheSize,
    uint8_t intermCacheSize,
    uint8_t featureSelection,
    uint8_t acManageCertRepo);

/** nx_SetConfig_WatchdogTimerMgmt
 * @brief Updates the Watchdog Timer Configurations.
 *
 * @param[in]   session_ctx       Session context.
 * @param[in]   hWDTValue         Halt Watchdog Timer (HWDT) Value.
 * @param[in]   aWDT1Value        Authorization Watchdog Timer 1 (AWDT1) Value.
 * @param[in]   aWDT2Value        Authorization Watchdog Timer 1 (AWDT2) Value.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_WatchdogTimerMgmt(
    pSeSession_t session_ctx, uint8_t hWDTValue, uint8_t aWDT1Value, uint8_t aWDT2Value);

/** nx_SetConfig_CryptoAPIMgmt
 * @brief Updates the Cryto API management configurations.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   cryptoAPISupport         Crypto API Support enable/disable Asymmetric and Symmetric Crypto APIs.
 * @param[in]   acCryptoRequest          Access Conditions for Cmd.CryptoRequest.
 * @param[in]   acChangeKey              Access Conditions for Cmd.ChangeKey targeting KeyID.CryptoRequestKey.
 * @param[in]   TBPolicyCount            Transient Buffer Policy Count.
 * @param[in]   TBPolicy                 Buffer contatining the Transient Buffer Policies.
 * @param[in]   SBPolicyCount            Static Buffer Policy Count.
 * @param[in]   SBPolicy                 Buffer contatining the Static Buffer Policies.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_CryptoAPIMgmt(pSeSession_t session_ctx,
    uint8_t cryptoAPISupport,
    uint8_t acCryptoRequest,
    uint8_t acChangeKey,
    uint8_t TBPolicyCount,
    Nx_slot_buffer_policy_t *TBPolicy,
    uint8_t SBPolicyCount,
    Nx_slot_buffer_policy_t *SBPolicy);

/** nx_SetConfig_AuthCounterLimit
 * @brief Updates the Authentication Counter options and Authentication Counter Limit Configuration.
 *
 * @param[in]   session_ctx        Session context.
 * @param[in]   authCtrFileID      Targeted Counter file ID.
 * @param[in]   authCtrOption      Authentication counter options.
 * @param[in]   authCtrLimit       Authentication Counter Limit.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_AuthCounterLimit(
    pSeSession_t session_ctx, uint8_t authCtrFileID, uint8_t authCtrOption, uint32_t authCtrLimit);

/** nx_SetConfig_HaltWakeupConfig
 * @brief Updates the HALT and Wake-up configuration of the card.
 *
 * @param[in]   session_ctx            Session context.
 * @param[out]   wakeupOptionA         Wake-up options (Byte A) bit 7 RFU, 6 GPIO wakeup is enables/disabled, 5-0 I2C Wakeup Address.
 * @param[out]   wakeupOptionB         Wake-up options (Byte B).
 * @param[out]   RDACSetting           RDAC Setting- impacts how much energy is drawn from RF field.
 * @param[out]   HALTOption            HALT options bit 1 GPIO2 reset, bit 0 GPIO1 reset.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_HaltWakeupConfig(
    pSeSession_t session_ctx, uint8_t wakeupOptionA, uint8_t wakeupOptionB, uint8_t RDACSetting, uint8_t HALTOption);

/** nx_SetConfig_DeferConfig
 * @brief Updates the defer configuration options.
 *
 * @param[in]   session_ctx        Session context.
 * @param[in]   deferralCount      Deferral Count (N).
 * @param[in]   deferralList       Deferral Method.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_DeferConfig(pSeSession_t session_ctx, uint8_t deferralCount, uint8_t *deferralList);

/** nx_SetConfig_LockConfig
 * @brief Updates the lock configurations.
 *
 * @param[in]   session_ctx        Session context.
 * @param[in]   lockBitMap         Four-byte value containing bitmap where each bit encodes for the related configuration option if it is locked.
 *
 * @return  status
*/
smStatus_t nx_SetConfig_LockConfig(pSeSession_t session_ctx, uint32_t lockBitMap);

/** nx_GetConfig_ManufactureConfig
 * @brief Gets the manufacturing prouct features.
 *
 * @param[in]   session_ctx        Session context.
 * @param[out]   productFeature     Contains the manufacturing product features of the card.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_ManufactureConfig(pSeSession_t session_ctx, uint16_t *productFeature);

/** nx_GetConfig_PICCConfig
 * @brief Gets the PICC configuration of the card.
 *
 * @param[in]   session_ctx        Session context.
 * @param[out]   PICCConfig         Pointer to byte containing the PICC configurations of the card.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_PICCConfig(pSeSession_t session_ctx, uint8_t *PICCConfig);

/** nx_GetConfig_ATSUpdate
 * @brief Gets the ATS configuration of the card.
 *
 * @param[in]   session_ctx       Session context.
 * @param[out]  userATS           Pointer to buffer containing the user defined ATS configurations.
 * @param[out]  userATSLen        Length of the buffer containing the user defined ATS configurations.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_ATSUpdate(pSeSession_t session_ctx, uint8_t *userATS, size_t *userATSLen);

/** nx_GetConfig_SAKUpdate
 * @brief Gets the SAK configuration of the card.
 *
 * @param[in]   session_ctx        Session context.
 * @param[out]   sak1              Pointer to SAK byte 1.
 * @param[out]   sak2              Pointer to SAK byte 2.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_SAKUpdate(pSeSession_t session_ctx, uint8_t *sak1, uint8_t *sak2);

/** nx_GetConfig_SMConfig
 * @brief Gets Secure Messaging configuration of the card.
 *
 * @param[in]   session_ctx        Session context.
 * @param[out]   SMConfigA           Pointer to double byte containing Secure Messaging Configuration RFU.
 * @param[out]   SMConfigB           Pointer to double byte containing EV2 secure messaging configuration.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_SMConfig(pSeSession_t session_ctx, uint8_t *SMConfigA, uint8_t *SMConfigB);

/** nx_GetConfig_CapData
 * @brief Gets PD Capability Data.
 *
 * @param[in]   session_ctx              Session context.
 * @param[out]   CapDataBuf               Capability data Buffer, consisting of 10 bytes: PDCap1 5th byte and PDCap2 6th byte
 * @param[out]   CapDataBufLen            Capability data Length, consisting of length Capability data Buffer
 *
 * @return  status
 */
smStatus_t nx_GetConfig_CapData(pSeSession_t session_ctx, uint8_t *CapDataBuf, uint8_t *CapDataBufLen);

/** nx_GetConfig_ATQAUpdate
 * @brief Gets ATQA configuration of the card.
 *
 * @param[in]   session_ctx        Session context.
 * @param[out]   userATQA          Pointer to double byte containing user defined ATQA value.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_ATQAUpdate(pSeSession_t session_ctx, uint16_t *userATQA);

/** nx_GetConfig_SilentModeConfig
 * @brief Gets Silent Mode configuration of the card.
 *
 * @param[in]   session_ctx          Session context.
 * @param[out]   silentMode          Pointer to byte containing Silent Mode configurations.
 * @param[out]   REQS                [optional] Pointer to Custom REQS, if silentMode[1] is true.
 * @param[out]   WUPS                [optional] Pointer to Custom WUPS, if silentMode[1] is true.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_SilentModeConfig(pSeSession_t session_ctx, uint8_t *silentMode, uint8_t *REQS, uint8_t *WUPS);

/** nx_GetConfig_EnhancedPrivacyConfig
 * @brief Gets Enhanced Privacy configuration of the card.
 *
 * @param[in]   session_ctx         Session context.
 * @param[out]   privacyOption               Pointer to Privacy Option Byte.
 * @param[out]   appPrivacyKey               Pointer to AppPrivacyKey definition.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_EnhancedPrivacyConfig(pSeSession_t session_ctx, uint8_t *privacyOption, uint8_t *appPrivacyKey);

/** nx_GetConfig_NFCMgmt
 * @brief Gets NFC Management configuration of the card.
 *
 * @param[in]   session_ctx          Session context.
 * @param[out]   nfcSupport           Pointer to byte containing NFC Support configuration.
 * @param[out]   protocolOptions      Pointer to two-byte map containing the crypto protocols supported over NFC.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_NFCMgmt(pSeSession_t session_ctx, uint8_t *nfcSupport, uint16_t *protocolOptions);

/** nx_GetConfig_I2CMgmt
 * @brief Gets I2C Management configuration of the card.
 *
 * @param[in]   session_ctx        Session context.
 * @param[out]   i2cSupport           Pointer to i2cSupport Bit 1-7 RFU, bit 0 if I2C I/O support is enabled/disabled.
 * @param[out]   i2cAddr              Pointer to The address used for I2C target.
 * @param[out]   protocolOptions      Pointer to Crypto protocols supported over I2C.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_I2CMgmt(
    pSeSession_t session_ctx, uint8_t *i2cSupport, uint8_t *i2cAddr, uint16_t *protocolOptions);

/** nx_GetConfig_GPIOMgmt
 * @brief Gets configuration of the card.
 *
 * @param[in]   session_ctx          Session context.
 * @param[out]   gpioConfig           Pointer to Structure containing all the GPIO related configurations.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_GPIOMgmt(pSeSession_t session_ctx, Nx_gpio_config_t *gpioConfig);

/** nx_GetConfig_EccKeyMgmt
 * @brief Gets ECC Key Management operations configuration of the card.
 *
 * @param[in]   session_ctx                Session context.
 * @param[out]   acManageKeyPair          Pointer to Access Condition for the ManageKeyPair operation.
 * @param[out]   acManageCARootKey        Pointer to Access Condition for the ManageCARootKey operation.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_EccKeyMgmt(pSeSession_t session_ctx, uint8_t *acManageKeyPair, uint8_t *acManageCARootKey);

/** nx_GetConfig_CertMgmt
 * @brief Gets Certificate Management configuration of the card.
 *
 * @param[in]   session_ctx              Session context.
 * @param[out]   leafCacheSize           Pointer to End leaf certificate cache size value.
 * @param[out]   intermCacheSize         Pointer to Intermediate certificate cache size value.
 * @param[out]   featureSelection        Feature Selection, Host Certificate Support, Internal Certificate Support and enable/disable SIGMA-I cache.
 * @param[out]   acManageCertRepo        Pointer to Access Conditions to manage certificate repository access value.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_CertMgmt(pSeSession_t session_ctx,
    uint8_t *leafCacheSize,
    uint8_t *intermCacheSize,
    uint8_t *featureSelection,
    uint8_t *acManageCertRepo);

/** nx_GetConfig_WatchdogTimerMgmt
 * @brief Gets Watchddog Timer configuration of the card.
 *
 * @param[in]   session_ctx   Session context.
 * @param[out]   hWDTValue         Pointer to Halt Watchdog Timer (HWDT) Value.
 * @param[out]   aWDT1Value        Pointer to Authorization Watchdog Timer 1 (AWDT1) Value.
 * @param[out]   aWDT2Value        Pointer to Authorization Watchdog Timer 1 (AWDT2) Value.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_WatchdogTimerMgmt(
    pSeSession_t session_ctx, uint8_t *hWDTValue, uint8_t *aWDT1Value, uint8_t *aWDT2Value);

/** nx_GetConfig_CryptoAPIMgmt
 * @brief Gets Crypto API Management configuration of the card.
 *
 * @param[in]   session_ctx             Session context.

 * @param[out]   acCryptoRequest          Pointer to Access Conditions for Cmd.CryptoRequest.
 * @param[out]   cryptoAPISupport         Pointer to Crypto API Support enable/disable Asymmetric and Symmetric Crypto APIs.
 * @param[out]   acChangeKey              Pointer to Access Conditions for Cmd.ChangeKey targeting KeyID.CryptoRequestKey.
 * @param[out]   TBPolicyCount            Pointer to Transient Buffer Policy Count.
 * @param[out]   TBPolicy                 Pointer to Buffer contatining the Transient Buffer Policies.
 * @param[out]   SBPolicyCount            Pointer to Static Buffer Policy Count.
 * @param[out]   SBPolicy                 Pointer to Buffer contatining the Static Buffer Policies.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_CryptoAPIMgmt(pSeSession_t session_ctx,
    uint8_t *cryptoAPISupport,
    uint8_t *acCryptoRequest,
    uint8_t *acChangeKey,
    uint8_t *TBPolicyCount,
    Nx_slot_buffer_policy_t *TBPolicy,
    uint8_t *SBPolicyCount,
    Nx_slot_buffer_policy_t *SBPolicy);

/** nx_GetConfig_AuthCounterLimit
 * @brief Gets Authentication Counter and Limit configuration of the card.
 *
 * @param[in]   session_ctx     Session context.
 * @param[out]   authCtrFileID      Pointer to Targeted Counter file ID.
 * @param[out]   authCtrOption      Pointer to Authentication counter options.
 * @param[out]   authCtrLimit       Pointer to Authentication Counter Limit.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_AuthCounterLimit(
    pSeSession_t session_ctx, uint8_t *authCtrFileID, uint8_t *authCtrOption, uint32_t *authCtrLimit);

/** nx_GetConfig_HaltWakeupConfig
 * @brief Gets HALT and Wake-up configuration of the card.
 *
 * @param[in]   session_ctx            Session context.
 * @param[out]   wakeupOptionA         Pointer to Wake-up options (Byte A) bit 7 RFU, 6 GPIO wakeup is enables/disabled, 5-0 I2C Wakeup Address.
 * @param[out]   wakeupOptionB         Pointer to Wake-up options (Byte B).
 * @param[out]   RDACSetting           Pointer to RDAC Setting- impacts how much energy is drawn from RF field.
 * @param[out]   HALTOption            Pointer to HALT options bit 1 GPIO2 reset, bit 0 GPIO1 reset.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_HaltWakeupConfig(pSeSession_t session_ctx,
    uint8_t *wakeupOptionA,
    uint8_t *wakeupOptionB,
    uint8_t *RDACSetting,
    uint8_t *HALTOption);

/** nx_GetConfig_DeferConfig
 * @brief Gets the defer configuration options.
 *
 * @param[in]   session_ctx        Session context.
 * @param[out]   deferralCount      Deferral Count (N).
 * @param[out]   deferralList       Deferral Method.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_DeferConfig(pSeSession_t session_ctx, uint8_t *deferralCount, uint8_t *deferralList);

/** nx_GetConfig_LockConfig
 * @brief Gets Lock configuration of the card.
 *
 * @param[in]   session_ctx      Session context.
 * @param[out]   lockMap         Pointer to Four-byte value containing bitmap where each bit encodes for the related configuration option if it is locked.
 *
 * @return  status
*/
smStatus_t nx_GetConfig_LockConfig(pSeSession_t session_ctx, uint32_t *lockMap);

/** nx_ReadCertRepo_Cert
 * @brief       Reads a certificate from a repository.
 *
 * @param[in]   session_ctx     Session context.
 * @param[in]   repoID          The Id of the Repository to read from.
 * @param[in]   dataItem        Data Item(End-leaf, Parent, Grand-parent, Repository Meta-data).
 * @param[out]  certificate     Certificate information as personalized into the certificate repository.
 * @param[out]  certificateLen  Length of the certificate.
 * @param[in]   knownCommMode   Communication mode of the repo known to the user.
 *
 * @return  status
*/
smStatus_t nx_ReadCertRepo_Cert(pSeSession_t session_ctx,
    uint8_t repoID,
    NX_CERTIFICATE_LEVEL_t dataItem,
    uint8_t *certificate,
    size_t *certificateLen,
    Nx_CommMode_t knownCommMode);

/** nx_ReadCertRepo_Metadata
 * @brief       Reads Meta-data of a repository.
 *
 * @param[in]   session_ctx      Session context.
 * @param   repoID           The Id of the Repository to read.
 * @param   privateKeyId     Id of ECC private key associated with this repository.
 * @param   repoSize         Memory reserved for the certificate repository.
 * @param   writeCommMode    Defines Communication Mode required to reset the repository.
 * @param   writeAccessCond  Defines the access right required to write this repository.
 * @param   readCommMode     Defines the Communication Mode required to read from the repository.
 * @param   readAccessCond   Defines the access right required to read from the repository.
 *
 * @return  status
*/
smStatus_t nx_ReadCertRepo_Metadata(pSeSession_t session_ctx,
    uint8_t repoID,
    uint8_t *privateKeyId,
    uint16_t *repoSize,
    Nx_CommMode_t *writeCommMode,
    uint8_t *writeAccessCond,
    Nx_CommMode_t *readCommMode,
    uint8_t *readAccessCond);

/** nx_ManageGPIO_Output
 * @brief       Manages the GPIO output.
 *
 * @param[in]      session_ctx          Session context.
 * @param[in]      gpioNo               GPIO Number(GPIO1/GPIO2).
 * @param[in]      operation            Targeted operation enable(true)/disable(false) NFC Action and GPIO output control.
 * @param[in,out]  nfcPauseRespData     Data received from the I2C interface.
 * @param[in,out]  nfcPauseRespDataLen  Length of data received from the I2C interface.
 * @param[in]      knownCommMode        Communication mode for GPIO Management.
 *
 * @return  status
*/
smStatus_t nx_ManageGPIO_Output(pSeSession_t session_ctx,
    uint8_t gpioNo,
    uint8_t operation,
    uint8_t *nfcPauseRespData,
    size_t nfcPauseRespDataLen,
    Nx_CommMode_t knownCommMode);

/** nx_ManageGPIO_PowerOut
 * @brief       Manages the GPIO Power output.
 *
 * @param[in]   session_ctx               Session context.
 * @param[in]   gpioNo                    GPIO Number(GPIO1/GPIO2).
 * @param[in]   operation                 Targeted operation voltage/current level enable(true)/disable(false) GPIO Measurement Control and  Power harvesting.
 * @param[out]  powerOutMeasureResult     Measurement result.
 * @param[in]   knownCommMode             Communication mode for GPIO Management.
 *
 * @return  status
*/
smStatus_t nx_ManageGPIO_PowerOut(pSeSession_t session_ctx,
    uint8_t gpioNo,
    uint8_t operation,
    uint8_t *powerOutMeasureResult,
    Nx_CommMode_t knownCommMode);

/** nx_ReadGPIO
 * @brief       Returns the GPIO status.
 *
 * @param[in]   session_ctx                       Session context.
 * @param[out]  tagTamperPermStatus               GPIO Byte 0 returns GPIO status (Close/Open/Invalid).
 * @param[out]  gpio1CurrentOrTTCurrentStatus     GPIO Byte 1 returns GPIO status (Close/Open/High/Low/Invalid).
 * @param[out]  gpio2CurrentStatus                GPIO Byte 2 returns GPIO status (High/Low/Invalid).
 * @param[in]   commMode                          Communication Mode of Read GPIO.
 *
 * @return  status
*/
smStatus_t nx_ReadGPIO(pSeSession_t session_ctx,
    Nx_GPIO_Status_t *tagTamperPermStatus,
    Nx_GPIO_Status_t *gpio1CurrentOrTTCurrentStatus,
    Nx_GPIO_Status_t *gpio2CurrentStatus,
    Nx_CommMode_t commMode);

/** nx_IncrCounterFile
 * @brief       Increments a Counter File.
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   fileNo           File number of the file to be incremented.
 * @param[in]   incrValue        Value to be incremented. LSB first.
 * @param[in]   knownCommMode     Communication Mode set by the user.
 *
 * @return  status
*/
smStatus_t nx_IncrCounterFile(
    pSeSession_t session_ctx, uint8_t fileNo, uint32_t incrValue, Nx_CommMode_t knownCommMode);
/** nx_GetFileCounters
 * @brief       Get file related counters, either used for Secure Dynamic Messaging for FileType StandardData, or from FileType Counter.
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   fileNo           File number of the targeted file.
 * @param[out]  counter          Returned counter for file types StandardData and Counter.
 * @param[in]   knownCommMode     Communication Mode set by the user.
 *
 * @return  status
*/
smStatus_t nx_GetFileCounters(pSeSession_t session_ctx, uint8_t fileNo, uint32_t *counter, Nx_CommMode_t knownCommMode);

/** nx_GetFileIDs
 * @brief       Returns the File IDentifiers of all active files within the currently selected application.
 *
 * @param[in]   session_ctx      Session context.
 * @param[out]  fIDList          List of n File IDs
 * @param[out]  fIDListLen       Length of fIDList.
 *
 * @return  status
*/
smStatus_t nx_GetFileIDs(pSeSession_t session_ctx, uint8_t *fIDList, size_t *fIDListLen);

/** nx_GetISOFileIDs
 * @brief       Get back the ISO File IDs.
 *
 * @param[in]   session_ctx      Session context.
 * @param[out]  fIDList          List of n ISO File IDs.
 * @param[out]  fIDListLen       Length of fIDList.
 *
 * @return  status
*/
smStatus_t nx_GetISOFileIDs(pSeSession_t session_ctx, uint8_t *fIDList, size_t *fIDListLen);

/** nx_ChangeKey
 * @brief       Depending on the currently selected AID, this command updates a key of an application.
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   objectID         Key ID of the key to be changed.
 * @param[in]   keyType          key Type of the key to be changed.
 * @param[in]   policy           Defines the allowed crypto operations with the targeted key
 * @param[in]   keyData          The new key.
 * @param[in]   keyDataLen       Length of the new Key.
 *
 * @return  status
*/
smStatus_t nx_ChangeKey(pSeSession_t session_ctx,
    uint8_t objectID,
    NX_KEY_TYPE_t keyType,
    uint16_t policy,
    uint8_t *keyData,
    size_t keyDataLen);

/** nx_GetKeySettings_AppKeys
 * @brief       Retrieves the meta-data of Application Keys.
 *
 * @param[in]   session_ctx      Session context.
 * @param[out]  keySetting       Key Setting.
 * @param[out]  keyType          Type of the key.
 * @param[out]  keyNumber        Key Number.
 *
 * @return  status
*/
smStatus_t nx_GetKeySettings_AppKeys(
    pSeSession_t session_ctx, uint8_t *keySetting, NX_KEY_TYPE_t *keyType, uint8_t *keyNumber);

/** nx_GetKeySettings_CryptoRequestKeyList
 * @brief       Retrieves the meta-data of Crypto Request Keys.
 *
 * @param[in]   session_ctx              Session context.
 * @param[out]  keyCount                 Number of key information entries (n) that will follow.
 * @param[out]  cryptoRequestKeyList     Crypto Request Key List with meta-data.
 *
 * @return  status
*/
smStatus_t nx_GetKeySettings_CryptoRequestKeyList(
    pSeSession_t session_ctx, uint8_t *keyCount, nx_crypto_key_meta_data_t *cryptoRequestKeyList);

/** nx_GetKeySettings_ECCPrivateKeyList
 * @brief       Retrieves the meta-data of ECC Private Keys.
 *
 * @param[in]   session_ctx              Session context.
 * @param[out]  keyCount                 Number of key information entries.
 * @param[out]  eccPrivateKeyList        Ecc Private Key List with meta-data.
 *
 * @return  status
*/
smStatus_t nx_GetKeySettings_ECCPrivateKeyList(
    pSeSession_t session_ctx, uint8_t *keyCount, nx_ecc_key_meta_data_t *eccPrivateKeyList);

/** nx_GetKeySettings_CARootKeyList
 * @brief       Retrieves the meta-data of CA Root Keys.
 *
 * @param[in]   session_ctx              Session context.
 * @param[out]  keyCount                 Number of key information entries.
 * @param[out]  caRootKeyList            CA Root Key list with meta-data.
 *
 * @return  status
*/
smStatus_t nx_GetKeySettings_CARootKeyList(
    pSeSession_t session_ctx, uint8_t *keyCount, nx_ca_root_key_meta_data_t *caRootKeyList);

/** nx_ManageCertRepo_CreateCertRepo
 * @brief       Creates the certificate repository.
 *
 * @param[in]   session_ctx         Session context.
 * @param[in]   repoID              Id used to identify certificate repository for algorithm execution and repository modification.
 * @param[in]   privateKeyId        Id of ECC private key associated with this repository.
 * @param[in]   repoSize            Memory reserved for the certificate repository.
 * @param[in]   writeCommMode       Defines Communication Mode required to Write the repository.
 * @param[in]   writeAccessCond     Defines the access right required to write the repository.
 * @param[in]   readCommMode        Defines the Communication Mode required to read from the repository.
 * @param[in]   readAccessCond      Defines the access right required to read from the repository
 * @param[in]   knownCommMode       Known Communication Mode.
 *
 * @return  status
*/
smStatus_t nx_ManageCertRepo_CreateCertRepo(pSeSession_t session_ctx,
    uint8_t repoID,
    uint8_t privateKeyId,
    uint16_t repoSize,
    Nx_CommMode_t writeCommMode,
    uint8_t writeAccessCond,
    Nx_CommMode_t readCommMode,
    uint8_t readAccessCond,
    Nx_CommMode_t knownCommMode);

/** nx_ManageCertRepo_LoadCert
 * @brief       load the certificate in the certificate chain.
 *
 * @param[in]   session_ctx    Session context.
 * @param[in]   repoID         The Id of the Repository to load the certificate to.
 * @param[in]   certLevel      Certificate Level (End-leaf,Parent,Grand-parent).
 * @param[in]   certBuf        Certificate Buffer.
 * @param[in]   certBufLen     Length of the Certificate Buffer.
 * @param[in]   knownCommMode       Known Communication Mode.
 *
 * @return  status
*/
smStatus_t nx_ManageCertRepo_LoadCert(pSeSession_t session_ctx,
    uint8_t repoID,
    NX_CERTIFICATE_LEVEL_t certLevel,
    const uint8_t *certBuf,
    uint16_t certBufLen,
    Nx_CommMode_t knownCommMode);

/** nx_ManageCertRepo_LoadCertMapping
 * @brief       loads a certificate mapping table to the repo.
 *
 * @param[in]   session_ctx        Session context.
 * @param[in]   repoID             The Id of the Repository to load the map to.
 * @param[in]   certLevel          Certificate Level (End-leaf,Parent,Grand-parent).
 * @param[in]   certMapping        Mapping data.
 * @param[in]   certMappingLen     Length of the mapping data.
 * @param[in]   knownCommMode       Known Communication Mode.
 *
 * @return  status
*/
smStatus_t nx_ManageCertRepo_LoadCertMapping(pSeSession_t session_ctx,
    uint8_t repoID,
    NX_CERTIFICATE_LEVEL_t certLevel,
    const uint8_t *certMapping,
    uint16_t certMappingLen,
    Nx_CommMode_t knownCommMode);

/** nx_ManageCertRepo_ResetRepo
 * @brief       Removes all repository content and reverts the repository to the state it was in immediately after creation.
 *
 * @param[in]   session_ctx         Session context.
 * @param[in]   repoID              The Id of the Repository to reset.
 * @param[in]   writeCommMode       Defines Communication Mode required to reset the repository.
 * @param[in]   writeAccessCond     Defines the access right required to reset the repository.
 * @param[in]   readCommMode        Defines the Communication Mode required to read from the repository.
 * @param[in]   readAccessCond      Defines the access right required to read from the repository.
 * @param[in]   knownCommMode       Known Communication Mode.
 *
 * @return  status
*/
smStatus_t nx_ManageCertRepo_ResetRepo(pSeSession_t session_ctx,
    uint8_t repoID,
    Nx_CommMode_t writeCommMode,
    uint8_t writeAccessCond,
    Nx_CommMode_t readCommMode,
    uint8_t readAccessCond,
    Nx_CommMode_t knownCommMode);

/** nx_ManageCertRepo_ActivateRepo
 * @brief       Activates the Certificate repository.
 *
 * @param[in]   session_ctx         Session context.
 * @param[in]   repoID              The Id of the Repository to be activated.
 * @param[in]   knownCommMode       Known Communication Mode.
 *
 * @return  status
*/
smStatus_t nx_ManageCertRepo_ActivateRepo(pSeSession_t session_ctx, uint8_t repoID, Nx_CommMode_t knownCommMode);

/** nx_GetKeyVersion
 * @brief   Returns key version of the key targeted depending on the currently selected AID and given key number parameter.
 *
 * @param[in]   session_ctx         Session context.
 * @param[in]   objectID            Key ID of the targeted key.
 * @param[out]  keyVer              Key version of the targeted key
 *
 * @return  status
*/
smStatus_t nx_GetKeyVersion(pSeSession_t session_ctx, uint8_t objectID, uint8_t *keyVer);

/** nx_CreateStdDataFile
 * @brief   Creates files for the storage of plain unformatted user data within an existing application on the PICC.
 *
 * @param[in]   session_ctx                Session context.
 * @param[in]   fileNo                     File number of the file to be created.
 * @param[in]   isoFileID                  ISO/IEC 7816-4 File ID f[in]or the file to be created.
 * @param[in]   fileOption                 FileOption Communication mode to be[in] used.
 * @param[in]   fileSize                   File size in bytes for t[in]he file to be created.
 * @param[in]   readAccessCondition        Read access Condition.
 * @param[in]   writeAccessCondition       Write access Condition.
 * @param[in]   readWriteAccessCondition   Read Write access Condition.
 * @param[in]   changeAccessCondition      Change access Condition.
 *
 * @return  status
*/
smStatus_t nx_CreateStdDataFile(pSeSession_t session_ctx,
    uint8_t fileNo,
    uint16_t isoFileID,
    uint8_t fileOption,
    size_t fileSize,
    Nx_AccessCondition_t readAccessCondition,
    Nx_AccessCondition_t writeAccessCondition,
    Nx_AccessCondition_t readWriteAccessCondition,
    Nx_AccessCondition_t changeAccessCondition);

/** nx_CreateCounterFile
 * @brief   Creates a Counter File.
 *
 * @param[in]   session_ctx                Session context.
 * @param[in]   fileNo                     File number of the file.
 * @param[in]   value                      Current Value.
 * @param[in]   fileOption                 Communication mode.
 * @param[in]   readAccessCondition        Read file access condition.
 * @param[in]   writeAccessCondition       Write file access condition.
 * @param[in]   readWriteAccessCondition   Read Write file Access condition.
 * @param[in]   changeAccessCondition      Change file access condition.
 *
 * @return  status
*/
smStatus_t nx_CreateCounterFile(pSeSession_t session_ctx,
    uint8_t fileNo,
    uint32_t value,
    uint8_t fileOption,
    Nx_AccessCondition_t readAccessCondition,
    Nx_AccessCondition_t writeAccessCondition,
    Nx_AccessCondition_t readWriteAccessCondition,
    Nx_AccessCondition_t changeAccessCondition);

/** nx_ChangeFileSettings
 * @brief Updates the file settings of the targeted file.
 *
 * @param[in]   session_ctx                Session context.
 * @param[in]   fileNo                     File No of the targeted file whose settings are to be changed.
 * @param[in]   fileOption                 fileOption used set Secure Dynamic Messaging and Mirroring, Deferred Configuration and Communication mode.
 * @param[in]   readAccessCondition        Read file access condition.
 * @param[in]   writeAccessCondition       Write file access condition.
 * @param[in]   readWriteAccessCondition   Read-Write file access condition.
 * @param[in]   changeAccessCondition      Change file access condition.
 * @param[in]   sdmConfig                  [Only if sdmEnabled is true] Pointer to structure containing SDM configurations.
 *
 * @return  status
*/
smStatus_t nx_ChangeFileSettings(pSeSession_t session_ctx,
    uint8_t fileNo,
    uint8_t fileOption,
    Nx_AccessCondition_t readAccessCondition,
    Nx_AccessCondition_t writeAccessCondition,
    Nx_AccessCondition_t readWriteAccessCondition,
    Nx_AccessCondition_t changeAccessCondition,
    nx_file_SDM_config_t *sdmConfig);

/** nx_GetFileSettings
 * @brief Reads the file settings of the targeted file.
 *
 * @param[in]   session_ctx                 Session context.
 * @param[in]   fileNo                      File No of the targeted file whose settings are to be read.
 * @param[out]   fileType                   Pointer to file type.
 * @param[out]   fileOption                 fileOption used set Secure Dynamic Messaging and Mirroring, Deferred Configuration and Communication mode.
 * @param[out]   readAccessCondition        Read file access condition.
 * @param[out]   writeAccessCondition       Write file access condition.
 * @param[out]   readWriteAccessCondition   Read-Write file access condition.
 * @param[out]   changeAccessCondition      Change file access condition.
 * @param[out]   fileSize                   Pointer to file size of the targeted file.
 * @param[out]   sdmConfig                  [Only if sdmEnabled is true] Pointer to structure containing SDM configurations.
 *
 * @return  status
*/
smStatus_t nx_GetFileSettings(pSeSession_t session_ctx,
    uint8_t fileNo,
    Nx_FILEType_t *fileType,
    uint8_t *fileOption,
    Nx_AccessCondition_t *readAccessCondition,
    Nx_AccessCondition_t *writeAccessCondition,
    Nx_AccessCondition_t *readWriteAccessCondition,
    Nx_AccessCondition_t *changeAccessCondition,
    size_t *fileSize,
    nx_file_SDM_config_t *sdmConfig);

/** nx_ReadData
 * @brief   Reads data from StandardData files.
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   fileNo           File number of the targeted file.
 * @param[in]   offset           Starting position for the read operation.
 * @param[in]   dataLen          Number of bytes to be read.
 * @param[out]  buffer           Data read.
 * @param[out]  bufferSize       size of data read.
 * @param[in]   knownCommMode     Communication Mode set by the user.
 *
 * @return  status
*/
smStatus_t nx_ReadData(pSeSession_t session_ctx,
    uint8_t fileNo,
    size_t offset,
    size_t dataLen,
    uint8_t *buffer,
    size_t *bufferSize,
    Nx_CommMode_t knownCommMode);

/** nx_WriteData
 * @brief   Writes data to FileType.StandardData files
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   fileNo           File Number of the targeted file.
 * @param[in]   offset           Starting position for the write operation
 * @param[in]   data             Data to be written.
 * @param[in]   dataLen          Number of bytes to be written.
 * @param[in]   knownCommMode     Communication Mode set by the user.
 *
 * @return  status
*/
smStatus_t nx_WriteData(pSeSession_t session_ctx,
    uint8_t fileNo,
    size_t offset,
    const uint8_t *data,
    size_t dataLen,
    Nx_CommMode_t knownCommMode);

/** nx_ISOInternalAuthenticate
 * @brief                  Asymmetric card-unilateral authentication.
 *
 * @param[in]   session_ctx    Session context.
 * @param[in]   privKeyNo          Targeted authentication key.
 * @param[in]   optsA          Optional TLV buffer from host.
 * @param[in]   optsALen       Length of OptsA buffer.
 * @param[in]   rndA           Buffer containing 16-byte random value from host.
 * @param[in]   rndALen        Length of rndA buffer.
 * @param[out]  rndB           Buffer containing 16-byte random value from card.
 * @param[out]  rndBLen        Length of rndB buffer.
 * @param[out]  sigB           Buffer containing Signature generated by card.
 * @param[out]  sigBLen        Length of sigB buffer.
 *
 * @return  status
*/
smStatus_t nx_ISOInternalAuthenticate(pSeSession_t session_ctx,
    uint8_t privKeyNo,
    uint8_t *optsA,
    size_t optsALen,
    uint8_t *rndA,
    size_t rndALen,
    uint8_t *rndB,
    size_t *rndBLen,
    uint8_t *sigB,
    size_t *sigBLen);

/** nx_ISOSelectFile
 * @brief   Selects an application or file
 *
 * @param[in]   session_ctx    Session context.
 * @param[in]   selectionCtl   Section Control.
 * @param[in]   option         ISO Select option (with/without FCI data).
 * @param[in]   data           Buffer containing ISO file type (MF/EF etc.) alongwith the identifier.
 * @param[in]   dataLen        Length of ISO file type data.
 * @param[out]  FCIData        FCI Data stored in file.
 * @param[out]  FCIDataLen     Length of FCI data stored in file.
 *
 * @return  status
*/
smStatus_t nx_ISOSelectFile(pSeSession_t session_ctx,
    Nx_ISOSelectCtl_t selectionCtl,
    Nx_ISOSelectOpt_t option,
    uint8_t *data,
    size_t dataLen,
    uint8_t *FCIData,
    size_t *FCIDataLen);

/** nx_ISOReadBinary_ShortFile
 * @brief Reads data from targeted file as encoded by P1.
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   shortISOFileID   ShortFile ID.
 * @param[in]   offset           offset.
 * @param[in]   data             Data read.
 * @param[in]   dataLen          Length of data read.
 *
 * @return  status
*/
smStatus_t nx_ISOReadBinary_ShortFile(
    pSeSession_t session_ctx, uint8_t shortISOFileID, size_t offset, uint8_t *data, size_t *dataLen);

/** nx_ISOReadBinary
 * @brief  Reads data from targeted file as encoded by P1.
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   offset           offset.
 * @param[in]   data             Data read.
 * @param[in]   dataLen          Length of data read.
 *
 * @return  status
*/
smStatus_t nx_ISOReadBinary(pSeSession_t session_ctx, size_t offset, uint8_t *data, size_t *dataLen);

/** nx_ISOUpdateBinary_ShortFile
 * @brief  Writes data to a targeted file as encoded by P1.
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   shortISOFileID   ShortFile ID.
 * @param[in]   offset           offset.
 * @param[in]   data             Data to be written.
 * @param[in]   dataLen          Length of data to be written.
 *
 * @return  status
*/
smStatus_t nx_ISOUpdateBinary_ShortFile(
    pSeSession_t session_ctx, uint8_t shortISOFileID, size_t offset, const uint8_t *data, size_t dataLen);

/** nx_ISOUpdateBinary
 * @brief  writes data to a targeted file as encoded by P1.
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   offset           Offset.
 * @param[in]   data             Data to be written.
 * @param[in]   dataLen          Length of data to be written.
 *
 * @return  status
*/
smStatus_t nx_ISOUpdateBinary(pSeSession_t session_ctx, size_t offset, const uint8_t *data, size_t dataLen);

/** nx_CryptoRequest_SHA_Init
 * @brief                        Initialize the SHA operation
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   algorithm        Algorithm to be used for sha calculation ('01': SHA-256, '02': SHA-384)
 * @param[in]   inputDataSrc     Source of input data (internal buffer/command buffer)
 * @param[in]   inputData        Input data when the input source is the command buffer
 * @param[in]   inputDataLen     Length of input data, only present when the input source is an internal buffer
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_SHA_Init(
    pSeSession_t session_ctx, uint8_t algorithm, uint8_t inputDataSrc, const uint8_t *inputData, size_t inputDataLen);

/** nx_CryptoRequest_SHA_Update
 * @brief                        Update the SHA Operation
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   algorithm        Algorithm to be used for sha calculation ('01': SHA-256, '02': SHA-384)
 * @param[in]   inputDataSrc     Source of input data (internal buffer/command buffer)
 * @param[in]   inputData        Input data when the input source is the command buffer
 * @param[in]   inputDataLen     Length of input data, only present when the input source is an internal buffer
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_SHA_Update(
    pSeSession_t session_ctx, uint8_t algorithm, uint8_t inputDataSrc, const uint8_t *inputData, size_t inputDataLen);

/** nx_CryptoRequest_SHA_Final
 * @brief                         Finalize the SHA Operation
 *
 * @param[in]    session_ctx      Session context.
 * @param[in]    algorithm        Algorithm to be used for sha calculation ('01': SHA-256, '02': SHA-384)
 * @param[in]    inputDataSrc     Source of input data (internal buffer/command buffer)
 * @param[in]    inputData        Input data when the input source is the command buffer
 * @param[in]    inputDataLen     Length of input data, only present when the input source is an internal buffer
 * @param[in]    resultDst        Destination of output data (internal buffer/command buffer)
 * @param[out]   outputData       SHA output hash
 * @param[out]   outputDataLen    Length of SHA output hash
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_SHA_Final(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData,
    size_t *outputDataLen);

/** nx_CryptoRequest_SHA_Oneshot
 * @brief                         Execute a SHA calculation using a single command
 *
 * @param[in]    session_ctx      Session context.
 * @param[in]    algorithm        Algorithm to be used for sha calculation ('01': SHA-256, '02': SHA-384)
 * @param[in]    inputDataSrc     Source of input data (internal buffer/command buffer)
 * @param[in]    inputData        Input data when the input source is the command buffer
 * @param[in]    inputDataLen     Length of input data, only present when the input source is an internal buffer
 * @param[in]    resultDst        Destination of output data (internal buffer/command buffer)
 * @param[out]   outputData       SHA output hash
 * @param[out]   outputDataLen    Length of SHA output hash
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_SHA_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData,
    size_t *outputDataLen);

/** nx_CryptoRequest_RNG
 * @brief                         Generate random data which is compliant with NIST SP800-90B using a 256-bit key.
 *
 * @param[in]    session_ctx      Session context.
 * @param[in]    rndLen           The number of bytes to generate (1 to 128)
 * @param[in]    resultDst        Destination of output data (internal buffer/command buffer)
 * @param[out]   outputData       Generated bytes of data
 * @param[out]   outputDataLen    The number of bytes generated
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_RNG(
    pSeSession_t session_ctx, uint8_t rndLen, uint8_t resultDst, uint8_t *outputData, size_t *outputDataLen);

/** nx_CryptoRequest_ECCSign_Init
 * @brief                        Initialize the ECC Signature Operation
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   algorithm        Algorithm to be used ('00': ECDSA with SHA256)
 * @param[in]   keyID            Id of the ECC key pair containing the private key to use.
 * @param[in]   inputSrc         Source of input data (internal buffer/command buffer)
 * @param[in]   inputData        Raw data bytes, only present when input source is the command buffer
 * @param[in]   inputDataLen     Length of input data, only present when the input source is an internal buffer
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_ECCSign_Init(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t keyID,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen);

/** nx_CryptoRequest_ECCSign_Update
 * @brief                        ECC Sign Update Operation
 *
 * @param[in]   session_ctx      Session context.
 * @param[in]   inputSrc         Source of input data (internal buffer/command buffer)
 * @param[in]   inputData        Raw data bytes, only present when input source is the command buffer
 * @param[in]   inputDataLen     Length of input data, only present when the input source is an internal buffer
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_ECCSign_Update(
    pSeSession_t session_ctx, uint8_t inputSrc, uint8_t *inputData, size_t inputDataLen);

/** nx_CryptoRequest_ECCSign_Final
 * @brief                         Finalize ECC Sign Operation
 *
 * @param[in]    session_ctx      Session context.
 * @param[in]    inputSrc         Source of input data (internal buffer/command buffer)
 * @param[in]    inputData        Raw data bytes, only present when input source is the command buffer
 * @param[in]    inputDataLen     Length of input data, only present when the input source is an internal buffer
 * @param[out]   outputSig        Output Signature data
 * @param[out]   outputSigLen     Length of signature data
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_ECCSign_Final(pSeSession_t session_ctx,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputSig,
    size_t *outputSigLen);

/** nx_CryptoRequest_ECCSign_Oneshot
 * @brief                         ECC signature operation in one shot
 *
 * @param[in]    session_ctx      Session context.
 * @param[in]    algorithm        Algorithm to be used ('00': ECDSA with SHA256)
 * @param[in]    keyID            Id of the ECC key pair containing the private key to use
 * @param[in]    inputSrc         Source of input data (internal buffer/command buffer)
 * @param[in]    inputData        Raw data bytes, only present when input source is the command buffer
 * @param[in]    inputDataLen     Length of input data, only present when the input source is an internal buffer
 * @param[out]   outputSig        Output Signature data
 * @param[out]   outputSigLen     Length of signature data
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_ECCSign_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t keyID,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputSig,
    size_t *outputSigLen);

/** nx_CryptoRequest_ECCSign_Digest_Oneshot
 * @brief                         ECC Signature Operation in one function
 *
 * @param[in]    session_ctx      Session context.
 * @param[in]    algorithm        Algorithm to be used ('00': ECDSA with SHA256)
 * @param[in]    keyID            Id of the ECC key pair containing the private key to use
 * @param[in]    inputSrc         Source of input data (internal buffer/command buffer)
 * @param[in]    inputData        Raw data bytes, only present when input source is the command buffer
 * @param[in]    inputDataLen     Length of input data, only present when the input source is an internal buffer
 * @param[out]   outputSig        Output Signature data
 * @param[out]   outputSigLen     Length of signature data
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_ECCSign_Digest_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t keyID,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputSig,
    size_t *outputSigLen);

/** nx_CryptoRequest_ECCVerify_Init
 * @brief                                Initialize the ECC Signature Verification Operation
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   algorithm                Algorithm to be used ('00' : ECDSA with SHA256)
 * @param[in]   curveID                  Curve to be used ('0C': NIST256, '0D': BP256)
 * @param[in]   hostPK                   The public key to use for signature verification.
 * @param[in]   hostPKLen                Length of the public key for signature verification.
 * @param[in]   inputSrc                 Source of input data (internal buffer/command buffer)
 * @param[in]   inputData                Raw data bytes, only present when input source is the command buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[out]  result                   Signature Verification init result
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_ECCVerify_Init(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t curveID,
    uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint16_t *result);

/** nx_CryptoRequest_ECCVerify_Update
 * @brief                            Update the ECC Signature Verification Operation
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   inputSrc                 Source of input data (internal buffer/command buffer)
 * @param[in]   inputData                Raw data bytes, only present when input source is the command buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[out]  result                   Signature Verification update result
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_ECCVerify_Update(
    pSeSession_t session_ctx, uint8_t inputSrc, uint8_t *inputData, size_t inputDataLen, uint16_t *result);

/** nx_CryptoRequest_ECCVerify_Final
 * @brief                            Finalize the ECC Signature Verification Operation
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   signature                Signature to verify
 * @param[in]   signatureLen             Length to Signature to verify
 * @param[in]   inputSrc                 Source of input data (internal buffer/command buffer)
 * @param[in]   inputData                Raw data bytes, only present when input source is the command buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[out]  result                   Signature Verification final result
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_ECCVerify_Final(pSeSession_t session_ctx,
    uint8_t *signature,
    size_t signatureLen,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint16_t *result);

/** nx_CryptoRequest_ECCVerify_Oneshot
 * @brief                                ECC Signature Verification Operation in one function
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   algorithm                Algorithm to be used ('00' : ECDSA with SHA256)
 * @param[in]   curveID                  Curve to be used ('0C': NIST256, '0D': BP256)
 * @param[in]   hostPK                   The public key to use for signature verification.
 * @param[in]   hostPKLen                Length of the public key for signature verification.
 * @param[in]   signature                Signature to verify
 * @param[in]   signatureLen             Length to Signature to verify
 * @param[in]   inputSrc                 Source of input data (internal buffer/command buffer)
 * @param[in]   inputData                Raw data bytes, only present when input source is the command buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[out]  result                   Signature Verification result
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_ECCVerify_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t curveID,
    uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t *signature,
    size_t signatureLen,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint16_t *result);

/** nx_CryptoRequest_ECCVerify_Digest_Oneshot
 * @brief                                ECC Signature Verification Operation using SHA256 in one function
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   algorithm                Algorithm to be used ('00' : ECDSA with SHA256)
 * @param[in]   curveID                  Curve to be used ('0C': NIST256, '0D': BP256)
 * @param[in]   hostPK                   The public key to use for signature verification.
 * @param[in]   hostPKLen                Length of the public key for signature verification.
 * @param[in]   signature                Signature to verify
 * @param[in]   signatureLen             Length to Signature to verify
 * @param[in]   inputSrc                 Source of input data (internal buffer/command buffer)
 * @param[in]   inputData                Raw data bytes, only present when input source is the command buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[out]  result                   Signature Verification result
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_ECCVerify_Digest_Oneshot(pSeSession_t session_ctx,
    uint8_t algorithm,
    uint8_t curveID,
    uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t *signature,
    size_t signatureLen,
    uint8_t inputSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint16_t *result);

/** nx_CryptoRequest_ECDH_Oneshot
 * @brief                                Generate ECDH Shared Secret
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   keyID                    Id of ECC key pair to use
 * @param[in]   sharedSecretDst          Source of shared secret (internal buffer/command buffer)
 * @param[in]   hostPK                   Host's public key
 * @param[in]   hostPKLen                Length of Host's public key
 * @param[out]  shareSecret              Shared Secret
 * @param[out]  shareSecretLen           Length of Shared Secret
 * @param[out]  pubKey                   Public Key
 * @param[out]  pubKeyLen                Length of Public Key
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_ECDH_Oneshot(pSeSession_t session_ctx,
    uint8_t keyID,
    uint8_t sharedSecretDst,
    const uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t *shareSecret,
    size_t *shareSecretLen,
    uint8_t *pubKey,
    size_t *pubKeyLen);

/** nx_CryptoRequest_ECDH_TwoStepPart1
 * @brief                            Generate ECDH Shared Secret Part 1
 *
 * @param[in]    session_ctx              Session context.
 * @param[in]    keyID                    Id of ECC key pair to use
 * @param[out]   pubKey                   Public Key
 * @param[out]   pubKeyLen                Length of Public Key
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_ECDH_TwoStepPart1(
    pSeSession_t session_ctx, uint8_t keyID, uint8_t *pubKey, size_t *pubKeyLen);

/** nx_CryptoRequest_ECDH_TwoStepPart2
 * @brief                                 Generate ECDH Shared Secret Part 2
 *
 * @param[in]    session_ctx              Session context.
 * @param[in]    keyID                    Id of ECC key pair to use
 * @param[in]    sharedSecretDst          Source of shared secret (internal buffer/command buffer)
 * @param[in]    hostPK                   Host's public key
 * @param[in]    hostPKLen                Length of Host's public key
 * @param[out]   shareSecret              Shared Secret
 * @param[out]   shareSecretLen           Length of SHared Secret
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_ECDH_TwoStepPart2(pSeSession_t session_ctx,
    uint8_t keyID,
    uint8_t sharedSecretDst,
    uint8_t *hostPK,
    size_t hostPKLen,
    uint8_t *shareSecret,
    size_t *shareSecretLen);

/** nx_CryptoRequest_AES_CMAC_Sign
 * @brief Generates the CMAC Signature for the given input data.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   operation                Enum denoting state of operation (init/update/final/oneshot).
 * @param[in]   keyID                    Key ID or internal buffer ID containing the private key to generate CMAC.
 * @param[in]   keyLen                   [Only when key ID is an internal buffer] Length of the private key (AES128/AES256).
 * @param[in]   inputDataSrc             Source of input data (internal buffer/command buffer).
 * @param[in]   inputData                Input data buffer.
 * @param[in]   inputDataLen             Length of input data buffer.
 * @param[out]   dstData                  Pointer to Buffer containing generated CMAC signature.
 * @param[out]   dstDataLen               Pointer to the length of generated CMAC signature.
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_CMAC_Sign(pSeSession_t session_ctx,
    Nx_MAC_Operation_t operation,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *dstData,
    size_t *dstDataLen);

/** nx_CryptoRequest_AES_CBC_ECB_Init
 * @brief AES CBC/ECB Initialize operation
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   aesPrimitive             Enum denoting AES primitive (ECB/CBC/sign/verify etc.)
 * @param[in]   keyID                   Key ID or internal buffer ID containing the private key for encryption/decryption.
 * @param[in]   keyLen                   [Only when key ID is an internal buffer] Length of the private key (AES128/AES256).
 * @param[in]   icvSrc                   [Only present for CBC operations] ICV source
 * @param[in]   icvData                  [Only present for CBC operations AND ICV source is command buffer] ICV Data Buffer
 * @param[in]   icvDataLen               Length of the ICV Buffer
 * @param[in]   inputDataSrc             Source of the Input Data to be encrypted/decrypted
 * @param[in]   inputData                [only present when input source is command buffer] Input data buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[out]   outputData               Pointer to Encrypted Output buffer
 * @param[out]   outputDataLen            Length of encrypted output buffer
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_CBC_ECB_Init(pSeSession_t session_ctx,
    Nx_AES_Primitive_t aesPrimitive,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t icvSrc,
    const uint8_t *icvData,
    size_t icvDataLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *outputDataLen);

/** nx_CryptoRequest_AES_CBC_ECB_Update
 * @brief AES CBC/ECB Update operation.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   inputDataSrc             Source of the Input Data to be encrypted/decrypted
 * @param[in]   inputData                [only present when input source is command buffer] Input data buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[out]   outputData               Pointer to Encrypted Output buffer
 * @param[out]   outputDataLen            Length of encrypted output buffer
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_CBC_ECB_Update(pSeSession_t session_ctx,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *outputDataLen);

/** nx_CryptoRequest_AES_CBC_ECB_Final
 * @brief AES CBC/ECB Finalize operation.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   inputDataSrc             Source of the Input Data to be encrypted/decrypted
 * @param[in]   inputData                [only present when input source is command buffer] Input data buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[out]   outputData               Pointer to Encrypted Output buffer
 * @param[out]   outputDataLen            Length of encrypted output buffer
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_CBC_ECB_Final(pSeSession_t session_ctx,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *outputData,
    size_t *outputDataLen);

/** nx_CryptoRequest_AES_CMAC_Verify
 * @brief Verifies the input data with the received CMAC Signature
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   operation                Enum denoting state of operation (init/update/final/oneshot).
 * @param[in]   keyID                    Key ID or internal buffer ID containing the private key to generate CMAC.
 * @param[in]   keyLen                   [Only when key ID is an internal buffer] Length of the private key (AES128/AES256).
 * @param[in]   inputDataSrc             Source of input data (internal buffer/command buffer).
 * @param[in]   inputData                Input data buffer.
 * @param[in]   inputDataLen             Length of input data buffer.
 * @param[in]   cmac_data                CMAC data buffer.
 * @param[in]   cmac_Len                 Length of CMAC data buffer.
 * @param[out]   verifyResult             Pointer to CMAC verification result value (5A5A- successful, A5A5- failed).
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_CMAC_Verify(pSeSession_t session_ctx,
    Nx_MAC_Operation_t operation,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *cmac_data,
    size_t cmac_Len,
    uint16_t *verifyResult);

/** nx_CryptoRequest_AES_CBC_ECB_Oneshot
 * @brief AES CBC/ECB Oneshot operation
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   aesPrimitive             Enum denoting AES primitive (ECB/CBC/sign/verify etc.)
 * @param[in]   keyID                   Key ID or internal buffer ID containing the private key for encryption/decryption.
 * @param[in]   keyLen                   [Only when key ID is an internal buffer] Length of the private key (AES128/AES256).
 * @param[in]   icvSrc                   [Only present for CBC operations] ICV source
 * @param[in]   icvData                  [Only present for CBC operations AND ICV source is command buffer] ICV Data Buffer
 * @param[in]   icvDataLen               Length of the ICV Buffer
 * @param[in]   inputDataSrc             Source of the Input Data to be encrypted/decrypted
 * @param[in]   inputData                [only present when input source is command buffer] Input data buffer
 * @param[in]   inputDataLen             Length of input data, only present when the input source is an internal buffer
 * @param[in]   resultDst                Destination of encrypted/decrypted data
 * @param[out]   outputData               Encrypted/decrypted output
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_CBC_ECB_Oneshot(pSeSession_t session_ctx,
    Nx_AES_Primitive_t aesPrimitive,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t icvSrc,
    const uint8_t *icvData,
    size_t icvDataLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData);

/** nx_CryptoRequest_AES_AEAD_Oneshot
 * @brief AES AEAD (CCM/GCM) Oneshot operation.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   action                   Action byte (encrypt/sign or decrypt/verify).
 * @param[in]   aesPrimitive             AES primitive (algorithm like CCM/GCM sign/verify etc.).
 * @param[in]   keyID                    Key ID
 * @param[in]   keyLen                   Length of the AES key (in bytes, 16 or 32)
 * @param[in]   nonceSrc                 [Not present when internally generated] Source of Nonce (internal buffer/command buffer).
 * @param[in]   nonceInput               [Not present when internally generated] Buffer containing Nonce data.
 * @param[in]   nonceDataLen             Length of Nonce data (CCM- 13 bytes, GCM- 12 to 60 bytes).
 * @param[out]   nonceOutput              [Only when nonce is internally generated] Pointer to buffer containing internally generated Nonce.
 * @param[in]   tagLen                   Length of the tag to be generated (CCM- 8 or 16 bytes, GCM- 12 to 16 bytes).
 * @param[in]   tagInput                 [Only for decrypt/verify primitive] Buffer containing input tag.
 * @param[out]   tagOutput                Pointer to buffer containing generated tag.
 * @param[in]   aadSrc                   AAD (Additional Associated Data) source.
 * @param[in]   aad                      AAD buffer.
 * @param[in]   aadLen                   Length of AAD buffer.
 * @param[in]   inputDataSrc             Input data source.
 * @param[in]   inputData                Input data buffer to be encrypted/decrypted.
 * @param[in]   inputDataLen             Length of Input buffer.
 * @param[in]   resultDst                Result destination.
 * @param[out]   verifyResult            [Only for decrypt/verify primitive] Verification result (5A5A- success, A5A5- failure).
 * @param[out]   outputData               Pointer to buffer with encrypted/decrypted output data.
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_AEAD_Oneshot(pSeSession_t session_ctx,
    uint8_t action,
    uint8_t aesPrimitive,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t nonceSrc,
    uint8_t *nonceInput,
    size_t nonceDataLen,
    uint8_t *nonceOutput,
    size_t tagLen,
    uint8_t *tagInput,
    uint8_t *tagOutput,
    uint8_t aadSrc,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint16_t *verifyResult,
    uint8_t *outputData);

/** nx_CryptoRequest_AES_AEAD_Init
 * @brief AES AEAD (CCM/GCM) Initialize operation.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   action                   Action byte (encrypt/sign or decrypt/verify).
 * @param[in]   aesPrimitive             AES primitive (algorithm like CCM/GCM sign/verify etc.).
 * @param[in]   keyID                    Key ID.
 * @param[in]   keyLen                   Length of the AES key (in bytes, 16 or 32)
 * @param[in]   nonceSrc                 [Not present when internally generated] Source of Nonce (internal buffer/command buffer).
 * @param[in]   nonceInput               [Not present when internally generated] Buffer containing Nonce data.
 * @param[in]   nonceDataLen             Length of Nonce data (CCM- 13 bytes, GCM- 12 to 60 bytes).
 * @param[out]   nonceOutput              [Only when nonce is internally generated] Pointer to buffer containing internally generated Nonce.
 * @param[in]   totalAadLen              Total number of AAD bytes
 * @param[in]   totalInputLen            Total number of input bytes
 * @param[in]   tagLen                   Length of the tag to be generated (CCM- 8 or 16 bytes, GCM- 12 to 16 bytes).
 * @param[in]   aadSrc                   AAD (Additional Associated Data) source.
 * @param[in]   aad                      AAD buffer.
 * @param[in]   aadLen                   Length of AAD buffer.
 * @param[in]   inputDataSrc             Input data source.
 * @param[in]   inputData                Input data buffer to be encrypted/decrypted.
 * @param[in]   inputDataLen             Length of Input buffer.
 * @param[in]   resultDst                Result destination.
 * @param[out]   outputData               Pointer to buffer with encrypted/decrypted output data.
 * @param[out]   outputDataLen               Pointer to length of buffer with encrypted/decrypted output data.
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_AEAD_Init(pSeSession_t session_ctx,
    uint8_t action,
    uint8_t aesPrimitive,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t nonceSrc,
    uint8_t *nonceInput,
    size_t nonceDataLen,
    uint8_t *nonceOutput,
    size_t totalAadLen,
    size_t totalInputLen,
    size_t tagLen,
    uint8_t aadSrc,
    uint8_t *aad,
    size_t aadLen,
    uint8_t inputDataSrc,
    uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData,
    size_t *outputDataLen);

/** nx_CryptoRequest_AES_AEAD_Update
 * @brief AES AEAD (CCM/GCM) Update operation.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   action                   Action byte (encrypt/sign or decrypt/verify).
 * @param[in]   aadSrc                   AAD (Additional Associated Data) source.
 * @param[in]   aad                      AAD buffer.
 * @param[in]   aadLen                   Length of AAD buffer.
 * @param[in]   inputDataSrc             Input data source.
 * @param[in]   inputData                Input data buffer to be encrypted/decrypted.
 * @param[in]   inputDataLen             Length of Input buffer.
 * @param[in]   resultDst                Result destination.
 * @param[out]   outputData               Pointer to buffer with encrypted/decrypted output data.
 * @param[out]   outputDataLen               Pointer to length of buffer with encrypted/decrypted output data.
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_AEAD_Update(pSeSession_t session_ctx,
    uint8_t action,
    uint8_t aadSrc,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *outputData,
    size_t *outputDataLen);

/** nx_CryptoRequest_AES_AEAD_Final
 * @brief AES AEAD (CCM/GCM) Final operation.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   action                   Action byte (encrypt/sign or decrypt/verify).
 * @param[in]   aadSrc                   AAD (Additional Associated Data) source.
 * @param[in]   aad                      AAD buffer.
 * @param[in]   aadLen                   Length of AAD buffer.
 * @param[in]   tagLen                   Length of the tag to be generated (CCM- 8 or 16 bytes, GCM- 12 to 16 bytes).
 * @param[in]   tagInput                 [Only for decrypt/verify primitive] Buffer containing input tag.
 * @param[out]   tagOutput                Pointer to buffer containing generated tag.
 * @param[in]   inputDataSrc             Input data source.
 * @param[in]   inputData                Input data buffer to be encrypted/decrypted.
 * @param[in]   inputDataLen             Length of Input buffer.
 * @param[in]   resultDst                Result destination.
 * @param[out]   verifyResult            [Only for decrypt/verify primitive] Verification result (5A5A- success, A5A5- failure).
 * @param[out]   outputData               Pointer to buffer with encrypted/decrypted output data.
 * @param[out]   outputDataLen               Pointer to length of buffer with encrypted/decrypted output data.
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_AES_AEAD_Final(pSeSession_t session_ctx,
    uint8_t action,
    uint8_t aadSrc,
    uint8_t *aad,
    size_t aadLen,
    size_t tagLen,
    uint8_t *tagInput,
    uint8_t *tagOutput,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint16_t *verifyResult,
    uint8_t *outputData,
    size_t *outputDataLen);

/** nx_CryptoRequest_Write_Internal_Buffer
 * @brief Writes data to an internal buffer (static/transient)
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   dst                      ID of the internal buffer.
 * @param[in]   dstData                  Buffer containing data to be written in an internal buffer.
 * @param[in]   dstDataLen               Length of the data.
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_Write_Internal_Buffer(
    pSeSession_t session_ctx, uint8_t dst, const uint8_t *dstData, size_t dstDataLen);

/** nx_CryptoRequest_HMAC_Sign
 * @brief Generates the HMAC Signature for the given input data.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   hmacOperation            Enum denoting state of hmac operation (init/update/final/oneshot).
 * @param[in]   digestAlgorithm          SHA algorithm to be used for generating HMAC.
 * @param[in]   keyID                    Key ID or internal buffer ID containing the private key to generate CMAC.
 * @param[in]   keyLen                   [Only when key ID is an internal buffer] Length of the private key (AES128/AES256).
 * @param[in]   inputDataSrc             Source of input data (internal buffer/command buffer).
 * @param[in]   inputData                Input data buffer.
 * @param[in]   inputDataLen             Length of input data buffer.
 * @param[in]   resultDst                [Only in finalize and oneshot operations] Result HMAC destination.
 * @param[out]   hmacOutput                  Pointer to Buffer containing generated CMAC signature.
 * @param[out]   hmacOutputLen               Pointer to the length of generated CMAC signature.
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_HMAC_Sign(pSeSession_t session_ctx,
    Nx_MAC_Operation_t hmacOperation,
    SE_DigestMode_t digestAlgorithm,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t resultDst,
    uint8_t *hmacOutput,
    size_t *hmacOutputLen);

/** nx_CryptoRequest_HMAC_Verify
 * @brief Verifies the input data with the received HMAC Signature
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   hmacOperation                Enum denoting state of operation (init/update/final/oneshot).
 * @param[in]   digestAlgorithm          SHA algorithm used in generating the HMAC signature of the received data.
 * @param[in]   keyID                    Key ID or internal buffer ID containing the private key to generate CMAC.
 * @param[in]   keyLen                   [Only when key ID is an internal buffer] Length of the private key (AES128/AES256).
 * @param[in]   inputDataSrc             Source of input data (internal buffer/command buffer).
 * @param[in]   inputData                Input data buffer.
 * @param[in]   inputDataLen             Length of input data buffer.
 * @param[in]   hmac                     HMAC data buffer.
 * @param[in]   hmac_len                 Length of HMAC data buffer.
 * @param[out]   verifyResult             Pointer to HMAC verification result value (5A5A- successful, A5A5- failed).
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_HMAC_Verify(pSeSession_t session_ctx,
    uint8_t hmacOperation,
    SE_DigestMode_t digestAlgorithm,
    uint8_t keyID,
    uint8_t keyLen,
    uint8_t inputDataSrc,
    const uint8_t *inputData,
    size_t inputDataLen,
    uint8_t *hmac,
    size_t hmac_len,
    uint16_t *verifyResult);

/** nx_CryptoRequest_HKDF
 * @brief Performs HKDF operations (Extract and Expand/Expand only)
 *
 * @param[in] session_ctx               Session context.
 * @param[in] hkdfOperation             HKDF operation (extract and expand/ expand only)
 * @param[in] digestOperation           SHA algorithm
 * @param[in] keyId                     Key ID or internal buffer ID containing the private key.
 * @param[in] keyLength                 [Only when key ID is an internal buffer] Length of the private key (AES128/AES256).
 * @param[in] saltSrc                   Salt source (Internal buffer/command buffer)
 * @param[in] saltData                  [Only if saltSrc is command buffer] Salt data buffer
 * @param[in] saltDataLen               Length of salt (0-128 bytes)- If salt length is 0 then a zero salt value of hash length bytes shall be used.
 * @param[in] infoSrc                   Info source
 * @param[in] infoData                  [Only if infoSrc is command buffer] Info data buffer
 * @param[in] infoDataLen               Length of info (0-80 bytes)
 * @param[in] resultDst                 Result destination (internal buffer/command buffer)
 * @param[in] resultLen                 Length of expected output in bytes
 * @param[out] hkdfOutput                Pointer to buffer with HKDF output
 * @param[out] hkdfOutputLen              Length of HKDF output
 *
 * @return  status
 */
smStatus_t nx_CryptoRequest_HKDF(pSeSession_t session_ctx,
    uint8_t hkdfOperation,
    uint8_t digestOperation,
    uint8_t keyId,
    size_t keyLength,
    uint8_t saltSrc,
    const uint8_t *saltData,
    size_t saltDataLen,
    uint8_t infoSrc,
    const uint8_t *infoData,
    size_t infoDataLen,
    uint8_t resultDst,
    size_t resultLen,
    uint8_t *hkdfOutput,
    size_t *hkdfOutputLen);

/** nx_CryptoRequest_ECHO
 * @brief       Additional Data bytes to echo, useful to verify system setup.
 *
 * @param[in]   session_ctx             Session context
 * @param[in]   additionalData          Additional bytes to echo
 * @param[in]   additionalDataLen       Length of Additional bytes to echo
 * @param[out]  rspaction               action byte FD:echo
 * @param[out]  rspadditionalData       Responce of Additional bytes to echo
 * @param[out]  rspadditionalDataLen    Responce of Additional Data Length
 *
 * @return  status
*/
smStatus_t nx_CryptoRequest_ECHO(pSeSession_t session_ctx,
    uint8_t *additionalData,
    size_t additionalDataLen,
    uint8_t *rspaction,
    uint8_t *rspadditionalData,
    size_t *rspadditionalDataLen);

/** Se_Create_AdditionalFrameRequest
 * @brief Creates additional frame request in secure tunneling.
 *
 * @param[in]  header pointer to header buffer
 *
 * @return  status
 */
smStatus_t Se_Create_AdditionalFrameRequest(tlvHeader_t *header);

/** nx_ProcessSM_Apply
 * @brief  Applies secure messaging for the given command.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   commMode                 Communication Mode.
 * @param[in]   offset                   Index of the first byte of CmdData in Data field.
 * @param[in]   cmdCtrIncr               Command counter increment value.
 * @param[in]   plainData                Plain data to protect.
 * @param[in]   plainDataLen             Length of Plain Data to Protect.
 * @param[out]  cipherData               Encrypted data
 * @param[out]  cipherDataLen            Length of encrypted data.
 *
 * @return  status
 */
smStatus_t nx_ProcessSM_Apply(pSeSession_t session_ctx,
    Nx_CommMode_t commMode,
    uint8_t offset,
    uint8_t cmdCtrIncr,
    uint8_t *plainData,
    size_t plainDataLen,
    uint8_t *cipherData,
    size_t *cipherDataLen);

/** nx_get_comm_mode
 * @brief  Gets the commMode for given command byte.
 *
 * @param[in]   session_ctx              Session context.
 * @param[in]   knownCommMode            Communication Mode set by the user.
 * @param[in]   cmdByte                  Command byte value.
 * @param[out]  out_commMode             Get communication Mode data nx supported.
 * @param[out]  options                  Options is optional parameter can used to pass keyid or additional purpose.
 *
 * @return  status
 */
smStatus_t nx_get_comm_mode(pSeSession_t session_ctx,
    Nx_CommMode_t knownCommMode,
    uint8_t cmdByte,
    nx_ev2_comm_mode_t *out_commMode,
    void *options);

#ifdef __cplusplus
}
#endif

#endif /* NX_APDU_H */
