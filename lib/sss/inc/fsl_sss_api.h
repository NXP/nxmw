/*
 *
 * Copyright 2022-2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
/** @file */
#ifndef _FSL_SSS_H_
#define _FSL_SSS_H_

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if !defined(SSS_CONFIG_FILE)
#include "fsl_sss_config.h"
#else
#include SSS_CONFIG_FILE
#endif

#include "fsl_sss_policy.h"
#include "fsl_sss_config_option.h"
#include "fsl_sss_types.h"

/** Version of the SSS API */
#define SSS_API_VERSION (0x00000001u)

/** @brief Enum indicating results of the SSS API calls.
 *
 */
typedef enum
{
    /** Operation was successful */
    kStatus_SSS_Success = 0x5a5a5a5au,
    /** Operation failed */
    kStatus_SSS_Fail = 0x3c3c0000u,
    /** Operation not performed because some of the passed parameters
     * were found inappropriate */
    kStatus_SSS_InvalidArgument = 0x3c3c0001u,
    /** Where the underlying sub-system *supports* multi-threading,
     * Internal status to handle simultaneous access.
     *
     * This status is not expected to be returned to higher layers.
     * */
    kStatus_SSS_ResourceBusy = 0x3c3c0002u,
} sss_status_t;

/** Helper macro to set enum value */

#define SSS_ENUM(GROUP, INDEX) ((GROUP) | (INDEX))

/** @brief Enum indicating various Cryptographic subsystems.
 *
 */
typedef enum
{
    kType_SSS_SubSystem_NONE,
    /** Software based */
    kType_SSS_Software = SSS_ENUM(0x01 << 8, 0x00),
    kType_SSS_mbedTLS  = SSS_ENUM(kType_SSS_Software, 0x01),
    kType_SSS_OpenSSL  = SSS_ENUM(kType_SSS_Software, 0x02),
    /** Secure Authenticator */
    kType_SSS_SecureElement = SSS_ENUM(0x08 << 8, 0x00),
    /** To connect to nx subsystem */
    kType_SSS_SE_NX = SSS_ENUM(kType_SSS_SecureElement, 0x03),
    kType_SSS_SubSystem_LAST
} sss_type_t;

/** Destination connection type */
typedef enum
{
    /* Plain => Lowest level of security requested.
     *       => Probably a system with no mechanism to *identify* who
     *          has opened the session from host
     */
    /** Needs to be set when auth type is none authentication */
    kSSS_ConnectionType_Plain,
    /* Encrypted:
     *    Communication is guaranteed to be Encrypted.
     *    For SE => This would mean highest level of authentication.
     */
    /** Needs to be set when auth type is Sigma-I or Symmetric authentication */
    kSSS_ConnectionType_Encrypted
} sss_connection_type_t;

/** Helper macro to set enum values of AES algos */
#define SSS_ALGORITHM_START_AES (0x01)
/** Helper macro to set enum values of DES algos */
#define SSS_ALGORITHM_START_DES (0x02)
/** Helper macro to set enum values of SHA algos */
#define SSS_ALGORITHM_START_SHA (0x03)
/** Helper macro to set enum values of MAC algos */
#define SSS_ALGORITHM_START_MAC (0x04)
/** Helper macro to set enum values of DH algos */
#define SSS_ALGORITHM_START_DH (0x05)
/** Helper macro to set enum values of ECDSA algos */
#define SSS_ALGORITHM_START_ECDSA (0x06)

/* Not available outside this file */
/** Helper macro to set enum values various algos */
#define SSS_ENUM_ALGORITHM(GROUP, INDEX) (((SSS_ALGORITHM_START_##GROUP) << 8) | (INDEX))

/** @brief Enum indicating various crypto algorithm modes.
 *
 */
typedef enum /* _sss_algorithm */
{
    kAlgorithm_None,
    /* AES */
    kAlgorithm_SSS_AES_ECB        = SSS_ENUM_ALGORITHM(AES, 0x01),
    kAlgorithm_SSS_AES_CBC        = SSS_ENUM_ALGORITHM(AES, 0x02),
    kAlgorithm_SSS_AES_CTR        = SSS_ENUM_ALGORITHM(AES, 0x03),
    kAlgorithm_SSS_AES_GCM        = SSS_ENUM_ALGORITHM(AES, 0x04),
    kAlgorithm_SSS_AES_CCM        = SSS_ENUM_ALGORITHM(AES, 0x05),
    kAlgorithm_SSS_AES_GCM_INT_IV = SSS_ENUM_ALGORITHM(AES, 0x06),
    kAlgorithm_SSS_AES_CTR_INT_IV = SSS_ENUM_ALGORITHM(AES, 0x07),
    kAlgorithm_SSS_AES_CCM_INT_IV = SSS_ENUM_ALGORITHM(AES, 0x08),
    /* DES */
    kAlgorithm_SSS_DES_ECB            = SSS_ENUM_ALGORITHM(DES, 0x01),
    kAlgorithm_SSS_DES_CBC            = SSS_ENUM_ALGORITHM(DES, 0x02),
    kAlgorithm_SSS_DES_CBC_ISO9797_M1 = SSS_ENUM_ALGORITHM(DES, 0x05),
    kAlgorithm_SSS_DES_CBC_ISO9797_M2 = SSS_ENUM_ALGORITHM(DES, 0x06),
    /* DES3 */
    kAlgorithm_SSS_DES3_ECB            = SSS_ENUM_ALGORITHM(DES, 0x03),
    kAlgorithm_SSS_DES3_CBC            = SSS_ENUM_ALGORITHM(DES, 0x04),
    kAlgorithm_SSS_DES3_CBC_ISO9797_M1 = SSS_ENUM_ALGORITHM(DES, 0x07),
    kAlgorithm_SSS_DES3_CBC_ISO9797_M2 = SSS_ENUM_ALGORITHM(DES, 0x08),
    /* digest */
    kAlgorithm_SSS_SHA1   = SSS_ENUM_ALGORITHM(SHA, 0x01),
    kAlgorithm_SSS_SHA224 = SSS_ENUM_ALGORITHM(SHA, 0x02),
    kAlgorithm_SSS_SHA256 = SSS_ENUM_ALGORITHM(SHA, 0x03),
    kAlgorithm_SSS_SHA384 = SSS_ENUM_ALGORITHM(SHA, 0x04),
    kAlgorithm_SSS_SHA512 = SSS_ENUM_ALGORITHM(SHA, 0x05),
    /* MAC */
    kAlgorithm_SSS_CMAC_AES    = SSS_ENUM_ALGORITHM(MAC, 0x01), /* CMAC-128 */
    kAlgorithm_SSS_HMAC_SHA1   = SSS_ENUM_ALGORITHM(MAC, 0x02),
    kAlgorithm_SSS_HMAC_SHA224 = SSS_ENUM_ALGORITHM(MAC, 0x03),
    kAlgorithm_SSS_HMAC_SHA256 = SSS_ENUM_ALGORITHM(MAC, 0x04),
    kAlgorithm_SSS_HMAC_SHA384 = SSS_ENUM_ALGORITHM(MAC, 0x05),
    kAlgorithm_SSS_HMAC_SHA512 = SSS_ENUM_ALGORITHM(MAC, 0x06),
    kAlgorithm_SSS_DES_CMAC8   = SSS_ENUM_ALGORITHM(MAC, 0x07), /* Only with OneShot mode */
    /* Diffie-Helmann */
    kAlgorithm_SSS_ECDH = SSS_ENUM_ALGORITHM(DH, 0x02),
    /* ECDSA */
    kAlgorithm_SSS_ECDSA_SHA1   = SSS_ENUM_ALGORITHM(ECDSA, 0x01),
    kAlgorithm_SSS_ECDSA_SHA224 = SSS_ENUM_ALGORITHM(ECDSA, 0x02),
    kAlgorithm_SSS_ECDSA_SHA256 = SSS_ENUM_ALGORITHM(ECDSA, 0x03),
    kAlgorithm_SSS_ECDSA_SHA384 = SSS_ENUM_ALGORITHM(ECDSA, 0x04),
    kAlgorithm_SSS_ECDSA_SHA512 = SSS_ENUM_ALGORITHM(ECDSA, 0x05),
} sss_algorithm_t;

#undef SSS_ENUM_ALGORITHM

/** High level algorihtmic operations.
 *
 * Augmented by @ref sss_algorithm_t
 */
typedef enum
{
    kMode_SSS_Encrypt             = 1,  //!< Encrypt
    kMode_SSS_Decrypt             = 2,  //!< Decrypt
    kMode_SSS_Sign                = 3,  //!< Sign
    kMode_SSS_Verify              = 4,  //!< Verify
    kMode_SSS_ComputeSharedSecret = 5,  //!< Compute Shared Secret. e.g. Diffie-Hellman
    kMode_SSS_Digest              = 6,  //!< Message Digest
    kMode_SSS_Mac                 = 7,  //!< Message Authentication Code
    kMode_SSS_HKDF_ExpandOnly     = 8,  //!< HKDF Expand Only (RFC 5869)
    kMode_SSS_HKDF_ExtractExpand  = 9,  //!< HKDF Extract and Expand (RFC 5869)
    kMode_SSS_Mac_Validate        = 10, //!< MAC Validate
} sss_mode_t;

/**
 * Permissions of an object. Only apply to host crypto key object.
 */
typedef enum
{
    /** Can read (applicable) contents of the key.
     *
     *  @note This is not same as @ref kAccessPermission_SSS_Use.
     *
     *  Without reading, the object, the key can be used.
     */
    kAccessPermission_SSS_Read = (1u << 0),
    /** Can change the value of an object */
    kAccessPermission_SSS_Write = (1u << 1),
    /** Can use an object */
    kAccessPermission_SSS_Use = (1u << 2),
    /** Can delete an object */
    kAccessPermission_SSS_Delete = (1u << 3),
    /** Can change permissions applicable to an object */
    kAccessPermission_SSS_ChangeAttributes = (1u << 4),
    /** Bitwise OR of all sss_access_permission. */
    kAccessPermission_SSS_All_Permission = 0x1F,
} sss_access_permission_t;

/**
 * Persistent / Non persistent mode of a key
 */
typedef enum
{
    kKeyObject_Mode_None = 0, //!< kKeyObject_Mode_None
    /** Key object will be persisted in memory
     * and will retain it's value after a closed session
     */
    kKeyObject_Mode_Persistent = 1,
    /** Key Object will be stored in RAM.
     * It will lose it's contents after a session is closed
     */
    kKeyObject_Mode_Transient = 2,
} sss_key_object_mode_t;

/** Part of a key */
typedef enum
{
    kSSS_KeyPart_NONE,
    /** Applicable where we have Symmetric Keys, HMAC-key */
    kSSS_KeyPart_Default = 1,
    /** Public part of asymmetric key */
    kSSS_KeyPart_Public = 2,
    /** Private only part of asymmetric key */
    kSSS_KeyPart_Private = 3,
    /** Both, public and private part of asymmetric key */
    kSSS_KeyPart_Pair = 4,
} sss_key_part_t;

/** For all cipher types, key bit length is provides at the time key is inserted/generated */
typedef enum
{
    kSSS_CipherType_NONE = 0,
    kSSS_CipherType_AES, /*! For NX Secure Authenticator - Use this to access cryptoRequestKey */
    kSSS_CipherType_CMAC,
    kSSS_CipherType_HMAC,
    kSSS_CipherType_AppKeys,
    kSSS_CipherType_EC_NIST_P,    /*! Keys Part of NIST-P Family */
    kSSS_CipherType_EC_BRAINPOOL, /*! Keys Part of Brainpool Family */
    kSSS_CipherType_Binary,
    kSSS_CipherType_Certificate,
    kSSS_CipherType_CARootKeys_NIST_P,
    kSSS_CipherType_CARootKeys_BRAINPOOL,
    kSSS_CipherType_ReservedPin,
    kSSS_CipherType_BufferSlots, /*! Static / Transient Buffer slots. Applicable only for NX Secure Authenticator */
} sss_cipher_type_t;

/** Slot type */
typedef enum
{
    kSSS_Slot_Type_Transient = 0,
    kSSS_Slot_Type_Static    = 1,
} sss_slot_type_t;

/** @brief Root session
 *
 * This is a *singleton* for each connection (physical/logical)
 * to individual cryptographic system.
 */
typedef struct
{
    /** Indicates which security subsystem is selected.
     *
     *  This is set when @ref sss_session_open is successful */
    sss_type_t subsystem;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_SESSION_MAX_CONTEXT_SIZE];
    } extension;
} sss_session_t;

/** @brief Store for secure and non secure key objects within a cryptographic system.
 *
 * - A cryptographic system may have more than partitions to store such keys.
 *
 */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_session_t *session;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_KEY_STORE_MAX_CONTEXT_SIZE];
    } extension;
} sss_key_store_t;

/** @brief An object (secure / non-secure) within a Key Store.
 *
 */
typedef struct
{
    /** key store holding the data and other properties */
    sss_key_store_t *keyStore;
    /** The type/part of object is referneced from @ref sss_key_part_t */
    uint32_t objectType;
    /** cipherType type from @ref sss_cipher_type_t */
    uint32_t cipherType;
    /** Application specific key identifier. The keyId is kept in the key store
     * along with the key data and other properties. */
    uint32_t keyId;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_KEY_OBJECT_MAX_CONTEXT_SIZE];
    } extension;
} sss_object_t;

/** @brief Typedef for the symmetric crypto context */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_session_t *session;
    /** Key to be used for the symmetric operation */
    sss_object_t *keyObject;
    /** Algorithm to be applied, e.g AES_ECB / CBC */
    sss_algorithm_t algorithm;
    /** Mode of operation, e.g Encryption/Decryption */
    sss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_SYMMETRIC_MAX_CONTEXT_SIZE];
    } extension;
} sss_symmetric_t;

/** @brief Authenticated Encryption with Additional Data
 *
 */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_session_t *session;
    /** Key to be used for asymmetric */
    sss_object_t *keyObject;
    /** Algorithm to be used */
    sss_algorithm_t algorithm;
    /** High level operation (encrypt/decrypt) */
    sss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_AEAD_MAX_CONTEXT_SIZE];
    } extension;
} sss_aead_t;

/** Message Digest operations */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_session_t *session;
    /** Algorithm to be applied, e.g SHA1, SHA256 */
    sss_algorithm_t algorithm;
    /** Mode of operation, e.g Sign/Verify */
    sss_mode_t mode;
    /** Full digest length per algorithm definition. This field is initialized along with algorithm. */
    size_t digestFullLen;
    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_DIGEST_MAX_CONTEXT_SIZE];
    } extension;
} sss_digest_t;

/** @brief Message Authentication Code
 *
 */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_session_t *session;
    /** Key to be used for ... */
    sss_object_t *keyObject;
    /** Algorithm to be applied, e.g. MAC/CMAC */
    sss_algorithm_t algorithm;
    /** Mode of operation for MAC (kMode_SSS_Mac) */
    sss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_MAC_MAX_CONTEXT_SIZE];
    } extension;
} sss_mac_t;

/** @brief Asymmetric Cryptographic operations
 *
 * e.g. ECC.
 */
typedef struct
{
    /** Pointer to root session */
    sss_session_t *session;
    /** KeyObject used for Asymmetric operation */
    sss_object_t *keyObject;
    /** Algorithm to be applied, e.g. ECDSA */
    sss_algorithm_t algorithm;
    /** Mode of operation for the Asymmetric operation.
     *  e.g. Sign/Verify/Encrypt/Decrypt */
    sss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_ASYMMETRIC_MAX_CONTEXT_SIZE];
    } extension;
} sss_asymmetric_t;

/** Communication Modes */
typedef enum
{
    kCommMode_Plain = 0x00,
    kCommMode_MAC   = 0x01,
    kCommMode_FULL  = 0x03,
} sss_CommMode_t;

/** Header for a IS716 APDU */
typedef struct
{
    /** ISO 7816 APDU Header */
    uint8_t hdr[0   /* For Indentation */
                + 1 /* CLA */
                + 1 /* INS */
                + 1 /* P1 */
                + 1 /* P2 */
    ];
} tlvHeader_t;

/** Key derivation */
typedef struct
{
    /** Pointer to the session */
    sss_session_t *session;
    /** KeyObject used to derive key s*/
    sss_object_t *keyObject;
    /** Algorithm to be applied, e.g. ... */
    sss_algorithm_t algorithm;
    /** Mode of operation for .... e.g. ... */
    sss_mode_t mode;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_DERIVE_KEY_MAX_CONTEXT_SIZE];
    } extension;
} sss_derive_key_t;

/** Random number generator context */
typedef struct
{
    /** Pointer to the session */
    sss_session_t *session;

    /** Reserved memory for implementation specific extension */
    struct
    {
        uint8_t data[SSS_RNG_MAX_CONTEXT_SIZE];
    } context;

} sss_rng_context_t;

/*******************************************************************************
 * API
 ******************************************************************************/
#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @addtogroup sss_session
 * @{
 */

/**
 * @brief         Open session between application and a security subsystem.
 *
 *                Open virtual session between application (user context) and a
 *                security subsystem and function thereof. Pointer to session
 *                shall be supplied to all SSS APIs as argument. Low level SSS
 *                functions can provide implementation specific behaviour based
 *                on the session argument.
 *                Note: sss_session_open() must not be called concurrently from
 *                multiple threads. The application must ensure this.
 *
 * @param[in,out] session          Session context.
 * @param[in]     subsystem        Indicates which security subsystem is
 *                                 selected to be used.
 * @param[in]     application_id   ObjectId/AuthenticationID Connecting to:
 *          - ``application_id`` == 0 => Super use / Plaform user
 *          - Anything else => Authenticated user
 * @param[in]     connection_type  How are we connecting to the system.
 *          - Plain: Lowest level. On SE, it only works with non-authentication mode.
 *          - Encrypted: Highest level. On SE, it works with Sigma-I or Symm authentication.
 * @param[in,out] connectionData   subsystem specific connection parameters.
 *
 * @return        status
 */
sss_status_t sss_session_open(sss_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData);

/**
 * @brief Close session between application and security subsystem.
 *
 * This function closes a session which has been opened with a security subsystem.
 * All commands within the session must have completed before this function can be called.
 * The implementation must do nothing if the input ``session`` parameter is NULL.
 *
 * @param[in,out]   session Session context.
 *
 * @return The sss status.
 */
sss_status_t sss_session_close(sss_session_t *session);

/**
 *@}
 */ /* end of sss_session */

/**
 * @addtogroup sss_key_store
 * @{
 */

/** @brief Constructor for the key store context data structure.
 *
 * @param[out] keyStore Pointer to key store context. Key store context is updated on function return.
 * @param[in] session Session context.
 *
 * @return The sss status.
 */
sss_status_t sss_key_store_context_init(sss_key_store_t *keyStore, sss_session_t *session);

/** @brief Get handle to key store.
 *  If the key store already exists, nothing is allocated.
 *  If the key store does not exists, new empty key store is created and initialized.
 *  Key store context structure is updated with actual information.
 *
 * @param[out] keyStore Pointer to key store context. Key store context is updated on function return.
 * @param[in] keyStoreId Implementation specific ID, can be used in case security subsystem manages multiple different
 * key stores.
 *
 * @return The sss status.
 */
sss_status_t sss_key_store_allocate(sss_key_store_t *keyStore, uint32_t keyStoreId);

/** @brief This function moves data[] from memory to the destination key store.
 *
 * @param[in] keyStore Key store context
 * @param[in] keyObject Reference to a key and it's properties
 * @param[in] data Data to be stored in Key. When setting ecc private key only, do not include key header.
 * @param[in] dataLen Length of the data
 * @param[in] keyBitLen Crypto algorithm key bit length
 * @param[in] options Pointer to implementation specific options
 * @param[in] optionsLen Length of the options in bytes
 *
 * @return The sss status.
 */
sss_status_t sss_key_store_set_key(sss_key_store_t *keyStore,
    sss_object_t *keyObject,
    const uint8_t *data,
    size_t dataLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen);

/** @brief This function generates key[] in the destination key store.
 *
 * @param[in] keyStore Key store context
 * @param[in] keyObject Reference to a key and it's properties
 * @param[in] keyBitLen Crypto algorithm key bit length
 * @param[in] options Pointer to implementation specific options
 *
 * @return The sss status.
 */
sss_status_t sss_key_store_generate_key(
    sss_key_store_t *keyStore, sss_object_t *keyObject, size_t keyBitLen, void *options);

/** @brief This function exports plain key[] from key store. As Secure Authenticator doesn't support reading key value,
 * this funtion returned the ECC public key value stored in keyOject. These public key comes from generating ECC
 * keypair or ECDH with ephemeral key operation.
 *
 * @param[in] keyStore Key store context
 * @param[in] keyObject Reference to a key and it's properties
 * @param[in,out] data Plain key buffer. key is copied to this buffer.
 * @param[in,out] dataLen Buffer length. Length is overwritten with actual data length.
 * @param[out] pKeyBitLen Key bitlength in case of EC keys.
 *
 *
 * @return The sss status.
*/
sss_status_t sss_key_store_get_key(
    sss_key_store_t *keyStore, sss_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen);

/**
 * @brief      Delete / destroy allocated keyObect .
 *
 * @param[in]      keyStore   The key store
 * @param[in,out]  keyObject  The key object to be deleted
 *
 * @return     The sss status.
 */
sss_status_t sss_key_store_erase_key(sss_key_store_t *keyStore, sss_object_t *keyObject);

/** @brief Destructor for the key store context.
 *
 * @param[out]     keyStore   The key store
 *
 * @return     The sss status.
 */
void sss_key_store_context_free(sss_key_store_t *keyStore);

/** @brief Constructor for a key object data structure
 *  The function initializes keyObject data structure and associates it with a key store
 *  in which the plain key and other attributes are stored.
 *
 * @param[out] keyObject The key object
 * @param[in]  keyStore The key store
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 *
 * @return The sss status.
 */
sss_status_t sss_key_object_init(sss_object_t *keyObject, sss_key_store_t *keyStore);

/**
 * @brief         Allocate / pre-provision memory for new key
 *
 *                This API allows underlying cryptographic subsystems to perform
 *                preconditions of before creating any cryptographic key object.
 *
 * @param[in,out] keyObject      The object If required, update implementation
 *                               defined values inside the keyObject
 * @param[in]     keyId          Key ID.
 *                               For symmetric keys in nx se - key id should be in the range of 0x10 to 0x17.
 *                               For asymmetric CA root keys in nx se - key id should be in the range of 0x00 to 0x04.
 *                               For asymmetric key pair in nx se - key id should be in the range of 0x00 to 0x04.
 * @param[in]     keyPart        See @ref sss_key_part_t
 * @param[in]     cipherType     See @ref sss_cipher_type_t
 * @param[in]     keyByteLenMax  Maximum storage this type of key may need. For
 *                               systems that have their own internal allocation
 *                               table this would help
 * @param[in]     options        0 = Persistant Key (Default) or Transient Key.
 *                               See sss_key_object_mode_t
 *
 * @return        Status of object allocation.
 */
sss_status_t sss_key_object_allocate_handle(sss_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t keyPart,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options);

/**
 * @brief      Get handle to an existing allocated/provisioned/created Object
 *
 *             See @ref sss_key_object_allocate_handle.
 *
 *             After calling this API, Ideally keyObject should become equivlant
 *             to as set after the calling of @ref
 *             sss_key_object_allocate_handle api.
 *
 * @param[in,out]   keyObject  The key object
 * @param[in]       cipherType The cipher type of the key
 * @param[in]       keyId      The key identifier
 *
 * @return          The sss status.
 */
sss_status_t sss_key_object_get_handle(sss_object_t *keyObject, sss_cipher_type_t cipherType, uint32_t keyId);

/** @brief Destructor for the key object.
 *  The function frees key object context.
 *
 * @param[in]   keyObject Pointer to key object context.
 *
 * @return      The sss status.
 */
void sss_key_object_free(sss_object_t *keyObject);

/**
 *@}
 */ /* end of sss_key_store */

/**
 * @addtogroup sss_derive_key
 * @{
 */

/** @brief Derive key context init.
 *  The function initializes derive key context with initial values.
 *
 * @param[out]  context Pointer to derive key context.
 * @param[in]   session Associate SSS session with the derive key context.
 * @param[in]   keyObject Associate SSS key object with the derive key context.
 * @param[in]   algorithm One of the derive key algorithms defined by @ref sss_algorithm_t.
 * @param[in]   mode One of the modes defined by @ref sss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_derive_key_context_init(sss_derive_key_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @brief Asymmetric key derivation Diffie-Helmann
 *  The function cryptographically derives a key from another key.
 *  For example Diffie-Helmann.
 *
 * @param[in] context Pointer to derive key context.
 * @param[in] otherPartyKeyObject Public key of the other party in the Diffie-Helmann algorithm
 * @param[in,out] derivedKeyObject Reference to a derived key
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_derive_key_dh_one_go(
    sss_derive_key_t *context, sss_object_t *otherPartyKeyObject, sss_object_t *derivedKeyObject);

/** @brief Asymmetric key derivation Diffie-Helmann
 *  The function cryptographically derives a key from another key.
 *  For example Diffie-Helmann.
 *
 * @param[in] context Pointer to derive key context.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_derive_key_dh_two_step_part1(sss_derive_key_t *context);

/** @brief Asymmetric key derivation Diffie-Helmann
 *  The function cryptographically derives a key from another key.
 *  For example Diffie-Helmann.
 *
 * @param[in] context Pointer to derive key context.
 * @param[in] otherPartyKeyObject Public key of the other party in the Diffie-Helmann algorithm
 * @param[in,out] derivedKeyObject Reference to a derived key
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_derive_key_dh_two_step_part2(
    sss_derive_key_t *context, sss_object_t *otherPartyKeyObject, sss_object_t *derivedKeyObject);

/** @brief Symmetric key derivation
 *  The function cryptographically derives a key from another key.
 *  For example HKDF-ExtractandExpand, HKDF-Expand.
 *
 * @param[in] context Pointer to derive key context.
 * @param[in] saltObject key object with salt data, typically with some random data.
 * @param[in] info Input data buffer, typically with some fixed info.
 * @param[in] infoLen Length of info buffer in bytes.
 * @param[out] derivedKeyObject Output key object containing key derivation output
 * @param[in] deriveDataLen Requested length of output
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_derive_key_one_go(sss_derive_key_t *context,
    sss_object_t *saltObject,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen);

/** @brief Derive key context release.
 *  The function frees derive key context.
 *
 * @param[out] context Pointer to derive key context.
 *
 * @return     The sss status.
 */
void sss_derive_key_context_free(sss_derive_key_t *context);

/**
 *@}
 */ /* end of sss_derive_key */

/**
 * @addtogroup sss_asymmetric
 * @{
 */

/** @brief Asymmetric context init.
 *  The function initializes asymmetric context with initial values.
 *
 * @param[out] context Pointer to asymmetric crypto context.
 * @param[in] session Associate SSS session with asymmetric context.
 * @param[in] keyObject Associate SSS key object with asymmetric context.
 * @param[in] algorithm One of the asymmetric algorithms defined by @ref sss_algorithm_t.
 * @param[in] mode One of the modes defined by @ref sss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_asymmetric_context_init(sss_asymmetric_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @brief Asymmetric signature of a message digest
 *  The function signs a message digest.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] digest Input buffer containing the input message digest
 * @param[in] digestLen Length of the digest in bytes
 * @param[out] signature Output buffer written with the signature of the digest
 * @param[out] signatureLen Length of the signature in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_asymmetric_sign_digest(
    sss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen);

/** @brief Asymmetric verify of a message digest
 *  The function verifies a message digest.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] digest Input buffer containing the input message digest
 * @param[in] digestLen Length of the digest in bytes
 * @param[in] signature Input buffer containing the signature to verify
 * @param[in] signatureLen Length of the signature in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_asymmetric_verify_digest(
    sss_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen);

/** @brief Asymmetric signature of a message
 *  The function signs a message.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] srcData Input buffer containing the input message
 * @param[in] srcLen Length of the srcData in bytes
 * @param[out] signature Output buffer written with the signature of the srcData
 * @param[in,out] signatureLen Length of the signature in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_asymmetric_sign_one_go(
    sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** @brief Asymmetric signature of a message init
 *  The function signs a message.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] srcData Input buffer containing the input message
 * @param[in] srcLen Length of the srcData in bytes

 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */

sss_status_t sss_asymmetric_sign_init(sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @brief Asymmetric signature of a message update
 *  The function signs a message.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] srcData Input buffer containing the input message
 * @param[in] srcLen Length of the srcData in bytes

 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_asymmetric_sign_update(sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @brief Asymmetric signature of a message Finish
 *  The function signs a message.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] srcData Input buffer containing the input message
 * @param[in] srcLen Length of the srcData in bytes
 * @param[out] signature Output buffer written with the signature of the srcData
 * @param[in, out] signatureLen Length of the signature in bytes

 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */

sss_status_t sss_asymmetric_sign_finish(
    sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen);

/** @brief Asymmetric verify of a message
 *  The function verifies a message.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] srcData Input buffer containing the input message
 * @param[in] srcLen Length of the srcData in bytes
 * @param[in] signature Input buffer containing the signature to verify
 * @param[in] signatureLen Length of the signature in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */

sss_status_t sss_asymmetric_verify_one_go(
    sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen);

/** @brief Asymmetric verify of a message
 *  The function verifies a message.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] srcData Input buffer containing the input message
 * @param[in] srcLen  Length of input buffer in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_asymmetric_verify_init(sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @brief Asymmetric verify of a message
 *  The function verifies a message.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] srcData Input buffer containing the input message
 * @param[in] srcLen Length of the srcData in bytes
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_asymmetric_verify_update(sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen);

/** @brief Asymmetric verify of a message
 *  The function verifies a message.
 *
 * @param[in] context Pointer to asymmetric context.
 * @param[in] srcData Input buffer containing the input message
 * @param[in] srcLen Length of the srcData in bytes
 * @param[in] signature Input buffer containing the signature to verify
 * @param[in] signatureLen Length of the signature in bytes

 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_asymmetric_verify_finish(
    sss_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen);

/** @brief Asymmetric context release.
 *  The function frees asymmetric context.
 *
 * @param[out] context Pointer to asymmetric context.
 */
void sss_asymmetric_context_free(sss_asymmetric_t *context);

/**
 *@}
 */ /* end of sss_asymmetric */

/**
 * @addtogroup sss_crypto_symmetric
 * @{
 */

/** @brief Symmetric context init.
 *  The function initializes symmetric context with initial values.
 *
 * @param[out] context Pointer to symmetric crypto context.
 * @param[in] session Associate SSS session with symmetric context.
 * @param[in] keyObject Associate SSS key object with symmetric context.
 * @param[in] algorithm One of the symmetric algorithms defined by @ref sss_algorithm_t.
 * @param[in] mode One of the modes defined by @ref sss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_symmetric_context_init(sss_symmetric_t *context,
    sss_session_t *session,
    sss_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode);

/** @brief Symmetric cipher in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param[in] context Pointer to symmetric crypto context.
 * @param[in] iv Buffer containing the symmetric operation Initialization Vector. When using internal IV algorithms (only encrypt)
 * for SE, iv buffer will be filled with genereted Initialization Vector.
 * @param[in] ivLen Length of the Initialization Vector in bytes.
 * @param[in] srcData Buffer containing the input data (block aligned).
 * @param[out] destData Buffer containing the output data.
 * @param[in] dataLen Size of input and output data buffer in bytes.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_cipher_one_go(
    sss_symmetric_t *context, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen);

/** @brief Symmetric cipher init.
 *  The function starts the symmetric cipher operation.
 *
 * @param[in] context Pointer to symmetric crypto context.
 * @param[in] iv Buffer containing the symmetric operation Initialization Vector. When using internal IV algorithms (only encrypt)
 * for SE, iv buffer will be filled with genereted Initialization Vector.
 * @param[in] ivLen Length of the Initialization Vector in bytes.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_cipher_init(sss_symmetric_t *context, uint8_t *iv, size_t ivLen);

/** @brief Symmetric cipher update.
 * Input data does not have to be a multiple of block size. Subsequent calls to this function are possible.
 * Unless one or more calls of this function have supplied sufficient input data, no output is generated.
 * The cipher operation is finalized with a call to @ref sss_cipher_finish().
 *
 * @param[in] context Pointer to symmetric crypto context.
 * @param[in] srcData Buffer containing the input data.
 * @param[in] srcLen Length of the input data in bytes.
 * @param[out] destData Buffer containing the output data.
 * @param[in,out] destLen Length of the output data in bytes. Buffer length on entry, reflects actual output size on
 * return.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_cipher_update(
    sss_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @brief Symmetric cipher finalize.
 *
 * @param[in] context Pointer to symmetric crypto context.
 * @param[in] srcData Buffer containing final chunk of input data.
 * @param[in] srcLen Length of final chunk of input data in bytes.
 * @param[out] destData Buffer containing output data.
 * @param[in,out] destLen Length of output data in bytes. Buffer length on entry, reflects actual output size on
 * return.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_cipher_finish(
    sss_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @brief Symmetric context release.
 *  The function frees symmetric context.
 *
 * @param[out] context Pointer to symmetric crypto context.
 */
void sss_symmetric_context_free(sss_symmetric_t *context);
/**
 *@}
 */ /* end of sss_crypto_symmetric */

/**
 * @addtogroup sss_aead
 * @{
 */

/** @brief Aead context init.
 *  The function initializes aead context with initial values.
 *
 * @param context Pointer to aead context.
 * @param session Associate SSS session with aead context.
 * @param keyObject Associate SSS session with key object.
 * @param algorithm One of the aead algorithms defined by @ref sss_algorithm_t.
 * @param mode One of the modes defined by @ref sss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */

sss_status_t sss_aead_context_init(
    sss_aead_t *context, sss_session_t *session, sss_object_t *keyObject, sss_algorithm_t algorithm, sss_mode_t mode);

/** @brief Symmetric cipher finalize.
 *
 * @param context Pointer to symmetric crypto context.
 * @param srcData Buffer containing final chunk of input data.
 * @param destData Buffer containing output data.
 * @param[in,out] size Length of output data in bytes. Buffer length on entry, reflects actual output size on
 * @param nonce Buffer containing Nonce data.
 * @param[in,out] nonceLen Length of nonce data in bytes. Buffer length on entry, reflects actual nonce Length on
 * @param aad Buffer containing aad data.
 * @param[in] aadLen Length of aad data in bytes. Buffer length on entry, reflects actual aad Length on
 * @param tag Buffer containing tag data.
 * @param[in, out] tagLen Length of tag data in bytes. Buffer length on entry, reflects actual tag Length on
 * return.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_aead_one_go(sss_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

/** @brief Symmetric cipher finalize.
 *
 * @param context Pointer to symmetric crypto context.
 * @param nonce Buffer containing Nonce data.
 * @param[in,out] nonceLen Length of nonce data in bytes. Buffer length on entry, reflects actual nonce Length on
 * @param[in] aadLen Length of aad data in bytes.
 * @param[in] tagLen Length of tag data in bytes.
 * @param[in] payloadLen Length of total input data in bytes.
 * return.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_aead_init(
    sss_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

/** @brief Symmetric cipher finalize.
 *
 * @param context Pointer to symmetric crypto context.
 * @param aadData Buffer containing aad data.
 * @param[in] aadDataLen Length of aad data in bytes. Buffer length on entry, reflects actual aad Length on
 * return.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_aead_update_aad(sss_aead_t *context, const uint8_t *aadData, size_t aadDataLen);

/** @brief Symmetric cipher finalize.
 *
 * @param context Pointer to symmetric crypto context.
 * @param srcData Buffer containing final chunk of input data.
 * @param srcLen Length of final chunk of input data in bytes.
 * @param destData Buffer containing output data.
 * @param[in,out] destLen Length of output data in bytes. Buffer length on entry, reflects actual output size on
 * return.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_aead_update(
    sss_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen);

/** @brief Symmetric cipher finalize.
 *
 * @param context Pointer to symmetric crypto context.
 * @param srcData Buffer containing final chunk of input data.
 * @param srcLen Length of final chunk of input data in bytes.
 * @param destData Buffer containing output data.
 * @param[in,out] destLen Length of output data in bytes. Buffer length on entry, reflects actual output size on
 * @param tag Buffer containing tag data.
 * @param[in, out] tagLen Length of tag data in bytes. Buffer length on entry, reflects actual tag Length on
 * return.
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_aead_finish(sss_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen);

/** @brief Aead context release.
 *  The function frees symmetric context.
 *
 * @param context Pointer to Aead crypto context.
 */
void sss_aead_context_free(sss_aead_t *context);
/**
 *@}
 */ /* end of sss_aead */

/**
 * @addtogroup sss_digest
 * @{
 */

/** @brief Digest context init.
 *  The function initializes digest context with initial values.
 *
 * @param[out] context Pointer to digest context.
 * @param[in] session Associate SSS session with digest context.
 * @param[in] algorithm One of the digest algorithms defined by @ref sss_algorithm_t.
 * @param[in] mode One of the modes defined by @ref sss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_digest_context_init(
    sss_digest_t *context, sss_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode);

/** @brief Message digest in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param[in] context Pointer to digest context.
 * @param[in] message Input message
 * @param[in] messageLen Length of the input message in bytes
 * @param[out] digest Output message digest
 * @param[in,out] digestLen Message digest byte length
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_digest_one_go(
    sss_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen);

/** @brief Init for digest multi step operation.
 *
 * @param[in] context Pointer to digest context.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_digest_init(sss_digest_t *context);

/** @brief Update for digest multi step operation.
 *
 * @param[in] context Pointer to digest context.
 * @param[in] message Buffer with a message chunk.
 * @param[in] messageLen Length of the input buffer in bytes.
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_digest_update(sss_digest_t *context, const uint8_t *message, size_t messageLen);

/** @brief Finish for digest multi step operation.
 *
 * @param[in] context Pointer to digest context.
 * @param[out] digest Output message digest
 * @param[in,out] digestLen Message digest byte length
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_digest_finish(sss_digest_t *context, uint8_t *digest, size_t *digestLen);

/** @brief Digest context release.
 *  The function frees digest context.
 *
 * @param[out] context Pointer to digest context.
 */
void sss_digest_context_free(sss_digest_t *context);

/**
 *@}
 */ /* end of sss_digest */

/**
 * @addtogroup sss_rng
 * @{
 */

/**
 * @brief Initialise random generator context between application and a security subsystem.
 *
 * @param[out]   context random generator context.
 * @param[in]   session Session context.
 *
 * @return  sss status
 */
sss_status_t sss_rng_context_init(sss_rng_context_t *context, sss_session_t *session);

/**
 * @brief Generate random number.
 *
 * @param[in]   context random generator context.
 * @param[out]   random_data buffer to hold random data.
 * @param[in]   dataLen required random number length
 *
 * @return  sss status
 */
sss_status_t sss_rng_get_random(sss_rng_context_t *context, uint8_t *random_data, size_t dataLen);

/**
 * @brief free random genertor context.
 *
 * @param[out]   context generator context.
 *
 * @return  sss status
 */
sss_status_t sss_rng_context_free(sss_rng_context_t *context);

/**
 *@}
 */ /* end of sss_rng */

/**
 * @addtogroup sss_crypto_mac
 * @{
 */

/** @brief MAC context init.
 *  The function initializes mac context with initial values.
 *
 * @param[out] context Pointer to mac context.
 * @param[in] session Associate SSS session with mac context.
 * @param[in] keyObject Associate SSS key object with mac context.
 * @param[in] algorithm One of the mac algorithms defined by @ref sss_algorithm_t.
 * @param[in] mode One of the modes defined by @ref sss_mode_t.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 * @retval #kStatus_SSS_InvalidArgument One of the arguments is invalid for the function to execute.
 */
sss_status_t sss_mac_context_init(
    sss_mac_t *context, sss_session_t *session, sss_object_t *keyObject, sss_algorithm_t algorithm, sss_mode_t mode);

/** @brief Message MAC in one blocking function call.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param[in] context Pointer to mac context.
 * @param[in] message Input message
 * @param[in] messageLen Length of the input message in bytes
 * @param[in,out] mac Output message MAC
 * @param[in,out] macLen Computed MAC byte length
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_mac_one_go(
    sss_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen);

/** @brief Init mac for a message.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param[in] context Pointer to mac context.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_mac_init(sss_mac_t *context);

/** @brief Update mac for a message.
 *
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param[in] context Pointer to mac context.
 * @param[in] message Buffer with a message chunk.
 * @param[in] messageLen Length of the input buffer in bytes.
 * @returns Status of the operation
 *
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_mac_update(sss_mac_t *context, const uint8_t *message, size_t messageLen);

/** @brief Finish mac for a message.
 *  The function blocks current thread until the operation completes or an error occurs.
 *
 * @param[in] context Pointer to mac context.
 * @param[in,out] mac Output message MAC
 * @param[in,out] macLen Computed MAC byte length
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
sss_status_t sss_mac_finish(sss_mac_t *context, uint8_t *mac, size_t *macLen);

/** @brief MAC context release.
 *  The function frees mac context.
 *
 * @param[out] context Pointer to mac context.
 */
void sss_mac_context_free(sss_mac_t *context);
/**
 *@}
 */ /* end of sss_crypto_mac */

#if defined(__cplusplus)
}
#endif

#endif /* _FSL_SSS_H_ */
