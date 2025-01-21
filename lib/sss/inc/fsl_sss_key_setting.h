/*
 *
 * Copyright 2019,2022 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
/** @file */

#ifndef _FSL_SSS_KEY_SETTING_H_
#define _FSL_SSS_KEY_SETTING_H_

#if !defined(SSS_CONFIG_FILE)
#include "fsl_sss_config.h"
#else
#include SSS_CONFIG_FILE
#endif

#include "fsl_sss_types.h"

#define SSS_KEY_SETTING_CRYPTO_KEY_COUNT_MAX NX_KEY_SETTING_CRYPTO_KEY_MAX_ENTRY
#define SSS_KEY_SETTING_ECC_KEY_COUNT_MAX NX_KEY_SETTING_ECC_KEY_MAX_ENTRY
#define SSS_KEY_SETTING_CA_ROOT_KEY_COUNT_MAX NX_KEY_SETTING_CAROOTKEY_MAX_ENTRY

/** @defgroup sss_key_setting
 *
 * Key settings.
 */

/** @addtogroup sss_key_setting
 * @{ */

/** KeyID.AppKeys key settings */
typedef struct
{
    /** KeyType.AES128/KeyType.AES256 */
    size_t keyBitLen;
    /** Number of KeyID.AppKeys. */
    uint8_t keyNumber;
} sss_appKeys_setting_t;

/** KeyID.CryptoRequestKeys key settings */
typedef struct
{
    /** Number of KeyID.CryptoRequestKeys. */
    uint8_t keyID;
    /** KeyType.AES128/KeyType.AES256 */
    size_t keyBitLen;
    /** Key Policy */
    sss_policy_chgAesKey_u keyPolicy;
} sss_cryptoReqKeyMeta_t;

/** KeyID.CryptoRequestKeys key settings */
typedef struct
{
    /** Number of key information entries (n) that will follow. */
    uint8_t keyNumber;
    /** List with meta-data */
    sss_cryptoReqKeyMeta_t cryptoReqKeyMetaData[SSS_KEY_SETTING_CRYPTO_KEY_COUNT_MAX];
} sss_cryptoReqKeys_setting_t;

/** KeyID.CryptoRequestKeys key settings */
typedef struct
{
    /** Number of KeyID.CryptoRequestKeys. */
    uint8_t keyID;
    /** Curve ID */
    sss_cipher_type_t curveId;
    /** Policy */
    sss_policy_genEcKey_u keyPolicy;
} sss_nx_ECCPrivateKeyMeta_t;

/** KeyID.ECCPrivateKeys key settings */
typedef struct
{
    /** Number of key information entries (n) that will follow. */
    uint8_t keyNumber;
    /** List with meta-data */
    sss_nx_ECCPrivateKeyMeta_t ECCPrivateKeyMetaData[SSS_KEY_SETTING_ECC_KEY_COUNT_MAX];
} sss_eccPrivateKeys_setting_t;

/** KeyID.CryptoRequestKeys key settings */
typedef struct
{
    /** Number of KeyID.CryptoRequestKeys. */
    uint8_t keyID;
    /** Curve ID */
    sss_cipher_type_t curveId;
    /** AccessRights */
    sss_policy_updateCARootKey_u keyPolicy;
} sss_nx_caRootKeyMeta_t;

/** KeyID.CARootKeys key settings */
typedef struct
{
    /** Number of key information entries (n) that will follow. */
    uint8_t keyNumber;
    /** List with meta-data */
    sss_nx_caRootKeyMeta_t caRootKeyMetaData[SSS_KEY_SETTING_CA_ROOT_KEY_COUNT_MAX];
} sss_caRootKeys_setting_t;

/** Type of key settign */
typedef enum
{
    /** No policy applied */
    KKEYSetting_None = 0,
    KKEYSetting_AppKey,
    KKEYSetting_CryptoKey,
    KKEYSetting_ECCPrivateKey,
    KKEYSetting_CARootKey,
} sss_key_setting_type_u;

/** Key settings for Cmd.GetKeySettings */
typedef struct
{
    /** Secure Object Type */
    sss_key_setting_type_u keyType;

    /** Union of key settings based on the type of key
     */
    union {
        sss_appKeys_setting_t appKeys;
        sss_cryptoReqKeys_setting_t cryptoReqKeys;
        sss_eccPrivateKeys_setting_t eccPrivateKeys;
        sss_caRootKeys_setting_t caRootKeys;
    } setting;
} sss_key_setting_t;

/** @} */

#endif /* _FSL_SSS_KEY_SETTING_H_ */
