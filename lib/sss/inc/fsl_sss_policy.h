/*
 *
 * Copyright 2019,2020 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
/** @file */

#ifndef _FSL_SSS_POLICY_H_
#define _FSL_SSS_POLICY_H_

#if !defined(SSS_CONFIG_FILE)
#include "fsl_sss_config.h"
#else
#include SSS_CONFIG_FILE
#endif

#include "fsl_sss_types.h"

/** @defgroup sss_policy Policy
 *
 * Policies to restrict and control sessions and objects.
 */

/** @addtogroup sss_policy
 * @{ */

/** Type of policy */
typedef enum
{
    /** No policy applied */
    KPolicy_None,
    KPolicy_ChgAESKey,
    KPolicy_GenECKey,
    KPolicy_UpdateCARootKey
} sss_policy_type_u;

typedef struct
{
    /** HKDF */
    uint8_t hkdfEnabled : 1;
    /** HMAC */
    uint8_t hmacEnabled : 1;
    /** GCM/CCM Encrypt/Sign with internal NONCE only */
    uint8_t aeadEncIntEnabled : 1;
    /** GCM/CCM Encrypt/Sign */
    uint8_t aeadEncEnabled : 1;
    /** GCM/CCM Decrypt/Verify */
    uint8_t aeadDecEnabled : 1;
    /** ECB/CBC Encrypt */
    uint8_t ecb_cbc_EncEnabled : 1;
    /** ECB/CBC Decrypt */
    uint8_t ecb_cbc_DecEnabled : 1;
    /** MAC Sign */
    uint8_t macSignEnabled : 1;
    /** MAC Verify */
    uint8_t macVerifyEnabled : 1;
    /** Key Version */
    uint8_t keyVersion;
    /** Old key value for AppKey */
    uint8_t oldKey[SSS_MAX_KEY_DATA_SIZE];
    /** Old key value length */
    size_t oldKeyLen;
} sss_policy_chgAesKey_u;

typedef struct
{
    /** Freeze KeyUsageCtrLimit */
    uint8_t freezeKUCLimit : 1;
    /** ECC-based Card-Unilateral Authentication */
    uint8_t cardUnilateralEnabled : 1;
    /** ECC-based Secure Dynamic Messaging */
    uint8_t sdmEnabled : 1;
    /** Cmd.CryptoRequest ECC Sign */
    uint8_t eccSignEnabled : 1;
    /** Cmd.CryptoRequest ECC DH */
    uint8_t ecdhEnabled : 1;
    /** SIGMA-I Mutual Authentication */
    uint8_t sigmaiEnabled : 1;
    /** CommMode required to update the key with Cmd.ManageKeyPair */
    uint8_t writeCommMode;
    /** Access Condition required to update the key with Cmd.ManageKeyPair */
    uint8_t writeAccessCond;
    /** Key Usage Counter required to update the key with Cmd.ManageKeyPair */
    uint32_t kucLimit;
    /** User defined commMode for cmd.ManageKeyPair */
    uint8_t userCommMode;
} sss_policy_genEcKey_u;

typedef struct
{
    /** CommMode required to update the repository with Cmd.ManageCertRepo  */
    uint8_t writeCommMode;
    /** Access Condition required to update the repository with Cmd.ManageCertRepo */
    uint8_t writeAccessCond;
    /** CommMode required to read the repository with Cmd.ManageCertRepo  */
    uint8_t readCommMode;
    /** Access Condition required to read the repository with Cmd.ManageCertRepo */
    uint8_t readAccessCond;
} sss_policy_genCertRepo_u;

typedef struct
{
    /** Access rights associated with the KeyID.CARootKey */
    uint16_t acBitmap;
    /** CommMode required to update the key with Cmd.ManageCARootKey */
    uint8_t writeCommMode;
    /** Access Condition required to update the key with Cmd.ManageCARootKey */
    uint8_t writeAccessCond;
    /** Trusted issuer name */
    uint8_t issuer[256];
    /** Length of trusted issuer name */
    size_t issuerLen;
    /** User defined commMode for cmd.ManageCARootKey */
    uint8_t userCommMode;
} sss_policy_updateCARootKey_u;

/** Unique/individual policy.
 * For any operation, you need array of sss_policy_u.
 */
typedef struct
{
    /** Secure Object Type */
    sss_policy_type_u type;
    /** Union of applicable policies based on the type of object
     */
    union {
        sss_policy_chgAesKey_u chgAesKey;
        sss_policy_genEcKey_u genEcKey;
        sss_policy_updateCARootKey_u updCARootKey;
    } policy;
} sss_policy_u;

/** An array of policies @ref sss_policy_u */
typedef struct
{
    /** Array of unique policies, this needs to be allocated based  nPolicies */
    const sss_policy_u *policies[SSS_POLICY_COUNT_MAX];
    /** Number of policies */
    size_t nPolicies;
} sss_policy_t;

/** Communication Mode of the SSS APIs */
typedef enum
{
    /** No protection: message is transmitted in clear */
    kCommMode_SSS_Plain = 0x00,
    /** MAC protection for integrity and authenticity */
    kCommMode_SSS_Mac = 0x01,
    /** Full protection for integrity, authenticity and confidentiality */
    kCommMode_SSS_Full = 0x03,
    /** Invalid protection mode */
    kCommMode_SSS_NA = 0x7F,
} sss_commMode_t;

/** Condition value of the SSS APIs */
typedef enum
{
    /** free access over I2C */
    kAC_SSS_Free_I2C = 0x0D,
    /** free access */
    kAC_SSS_Free = 0x0E,
    /** no access or RFU */
    kAC_SSS_No_Access = 0x0F,
} sss_accessCondition_t;

/** @} */

#endif /* _FSL_SSS_POLICY_H_ */
