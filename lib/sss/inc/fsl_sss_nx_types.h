/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef SSS_APIS_INC_FSL_SSS_NX_TYPES_H_
#define SSS_APIS_INC_FSL_SSS_NX_TYPES_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "fsl_sss_api.h"
#include "fsl_sss_policy.h"

#if SSS_HAVE_NX_TYPE
#include "nx_secure_msg_types.h"
#include "nx_const.h"
#include "nx_apdu_tlv.h"
#include "sm_api.h"
#if __GNUC__ && ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) ||    \
                    (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
                    (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
#include <pthread.h>
/* Only for base session with os */
#endif
/* FreeRTOS includes. */
#if USE_RTOS
#include "FreeRTOS.h"
#include "FreeRTOSIPConfig.h"
#include "semphr.h"
#include "task.h"
#endif

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/** Are we using NX as crypto subsystem? */
#define SSS_SUBSYSTEM_TYPE_IS_NX(subsystem) (subsystem == kType_SSS_SE_NX)

/** Are we using NX as crypto subsystem? */
#define SSS_SESSION_TYPE_IS_NX(session) (session && SSS_SUBSYSTEM_TYPE_IS_NX(session->subsystem))

/** Are we using NX as crypto subsystem? */
#define SSS_KEY_STORE_TYPE_IS_NX(keyStore) (keyStore && SSS_SESSION_TYPE_IS_NX(keyStore->session))

/** Are we using NX as crypto subsystem? */
#define SSS_OBJECT_TYPE_IS_NX(pObject) (pObject && SSS_KEY_STORE_TYPE_IS_NX(pObject->keyStore))

/** Are we using NX as crypto subsystem? */
#define SSS_ASYMMETRIC_TYPE_IS_NX(context) (context && SSS_SESSION_TYPE_IS_NX(context->session))

/** Are we using NX as crypto subsystem? */
#define SSS_DERIVE_KEY_TYPE_IS_NX(context) (context && SSS_SESSION_TYPE_IS_NX(context->session))

/** Are we using NX as crypto subsystem? */
#define SSS_SYMMETRIC_TYPE_IS_NX(context) (context && SSS_SESSION_TYPE_IS_NX(context->session))

/** Are we using NX as crypto subsystem? */
#define SSS_MAC_TYPE_IS_NX(context) (context && SSS_SESSION_TYPE_IS_NX(context->session))

/** Are we using NX as crypto subsystem? */
#define SSS_RNG_CONTEXT_TYPE_IS_NX(context) (context && SSS_SESSION_TYPE_IS_NX(context->session))

/** Are we using NX as crypto subsystem? */
#define SSS_DIGEST_TYPE_IS_NX(context) (context && SSS_SESSION_TYPE_IS_NX(context->session))

/** Are we using NX as crypto subsystem? */
#define SSS_AEAD_TYPE_IS_NX(context) (context && SSS_SESSION_TYPE_IS_NX(context->session))

/** Are we using NX as repository subsystem? */
#define SSS_REPO_TYPE_IS_NX(repo) (repo && SSS_SESSION_TYPE_IS_NX(repo->session))

/** Are we using NX as gpio subsystem? */
#define SSS_GPIO_TYPE_IS_NX(gpio) (gpio && SSS_SESSION_TYPE_IS_NX(gpio->session))

/* ************************************************************************** */
/* Structrues and Typedefs                                                    */
/* ************************************************************************** */

/** @copydoc sss_session_t */
typedef struct _sss_nx_session
{
    /** Indicates which security subsystem is selected to be used. */
    sss_type_t subsystem;
    /** Connection context to NX */
    SeSession_t s_ctx;
} sss_nx_session_t;

typedef struct
{
    /** Pointer to the session */
    sss_nx_session_t *session;
} sss_nx_key_store_t;

/** @copydoc sss_object_t */
typedef struct _sss_nx_object
{
    /** key store holding the data and other properties */
    sss_key_store_t *keyStore;
    /** @copydoc sss_object_t::objectType */
    uint32_t objectType;
    /** @copydoc sss_object_t::cipherType */
    sss_cipher_type_t cipherType;
    /** Application specific key identifier. The keyId is kept in the key  store
     * along with the key data and other properties. */
    uint32_t keyId;
    /** If this is an ECC Key, the Curve ID of the key */
    Nx_ECCurve_t curve_id;
    /** When ec key is generated, public key will be stored here */
    uint8_t pubKey[128];
    /** Public key length */
    size_t pubKeyLen;
    /** Symm key length in byte. Used for internal key */
    uint8_t keyLen;
} sss_nx_object_t;

typedef struct
{
    /** Pointer to the session */
    sss_nx_session_t *session;
    /** KeyObject used to derive key s*/
    sss_nx_object_t *keyObject;
    /** Algorithm to be applied, e.g. ... */
    sss_algorithm_t algorithm;
    /** Mode of operation for .... e.g. ... */
    sss_mode_t mode;
} sss_nx_derive_key_t;

/** @copydoc sss_asymmetric_t */
typedef struct
{
    /** @copydoc sss_asymmetric_t::session */
    sss_nx_session_t *session;
    /** @copydoc sss_asymmetric_t::keyObject */
    sss_nx_object_t *keyObject;
    /** @copydoc sss_asymmetric_t::algorithm */
    sss_algorithm_t algorithm;
    /** @copydoc sss_asymmetric_t::mode */
    sss_mode_t mode;
} sss_nx_asymmetric_t;

/** @copydoc sss_symmetric_t */
typedef struct
{
    /** @copydoc sss_symmetric_t::session */
    sss_nx_session_t *session;
    /** @copydoc sss_symmetric_t::keyObject */
    sss_nx_object_t *keyObject;
    /** @copydoc sss_symmetric_t::algorithm */
    sss_algorithm_t algorithm;
    /** @copydoc sss_symmetric_t::mode */
    sss_mode_t mode;
} sss_nx_symmetric_t;

typedef struct _sss_nx_aead
{
    /*! Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_nx_session_t *session;
    sss_nx_object_t *keyObject; /*!< Reference to key and it's properties. */
    sss_algorithm_t algorithm;  /*!<  */
    sss_mode_t mode;            /*!<  */
} sss_nx_aead_t;

/** @copydoc sss_digest_t */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_nx_session_t *session;
    /** @copydoc sss_digest_t::algorithm */
    sss_algorithm_t algorithm;
    /** @copydoc sss_digest_t::mode */
    sss_mode_t mode;
    /** @copydoc sss_digest_t::init_done */
    bool init_done;
} sss_nx_digest_t;

/** @copydoc sss_nx_buffer_t */
typedef struct
{
    /** Virtual connection between application (user context) and specific
     * security subsystem and function thereof. */
    sss_nx_session_t *session;
} sss_nx_buffer_t;

/** @copydoc sss_nx_rng_context_t */
typedef struct
{
    /** @copydoc sss_nx_rng_context_t::session */
    sss_nx_session_t *session;
} sss_nx_rng_context_t;

/** @copydoc sss_nx_cfg_context_t */
typedef struct
{
    /** @copydoc sss_nx_cfg_context_t::session */
    sss_nx_session_t *session;
} sss_nx_cfg_context_t;

/**  */
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
} sss_nx_aes_key_policy_t;

/** @brief Individual entry in array of TLV commands */
typedef struct
{
    /** @copydoc  */
    uint8_t *pBuffer; //  commmand buffer pointer
    /** @copydoc  */
    size_t bufferLen; //  commmand buffer length
} nx_command_buffer_t;

/** @brief Individual entry in array of TLV commands */
typedef union {
    /** @copydoc  */
    uint8_t tBuffSlotNum; // Transient buffer slot number
    /** @copydoc  */
    nx_command_buffer_t cmdBuf; // commmand buffer
} nx_crypto_buffer_t;

typedef enum
{
    /** Transient buffer */
    NX_DATA_TYPE_TRANSIENT_BUFFER,
    /** Command buffer  */
    NX_DATA_TYPE_COMMAND_BUFFER,
} nx_crypto_data_type_t;

#define NX_Connect_Ctx_t nx_connect_ctx_t

typedef enum
{
    /** Operation was successful */
    file_operate_Success = 0x5a5a5a5au,
    /** Operation failed */
    file_operate_Fail = 0x3c3c0000u,
    /** Operation failed due to file not exist */
    file_not_exist = 0x3c3c0001u,
} file_status_t;

typedef struct
{
    /** copydoc sss_mac_t::session */
    sss_nx_session_t *session;
    /** copydoc sss_mac_t::keyObject */
    sss_nx_object_t *keyObject;
    /** copydoc sss_mac_t::algorithm */
    sss_algorithm_t algorithm;
    /** copydoc sss_mac_t::mode */
    sss_mode_t mode;
    /* Implementation specific part */
    /** To keep track of init function */
    bool init_done;
} sss_nx_mac_t;

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Functions                                                                  */
/* ************************************************************************** */

#endif /* SSS_HAVE_NX_TYPE */

#endif /* SSS_APIS_INC_FSL_SSS_NX_TYPES_H_ */
