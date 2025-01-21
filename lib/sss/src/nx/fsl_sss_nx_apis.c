/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_NX_TYPE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "fsl_sss_nx_apis.h"
#include "nxLog_msg.h"
#include "fsl_sss_policy.h"
#include "fsl_sss_key_setting.h"
#include "fsl_sss_config_option.h"
#include "fsl_sss_nx_auth_types.h"
#include "fsl_sss_util_asn1_der.h"
#include "nx_const.h"
#include "sm_api.h"
#include "nxEnsure.h"
#include "nx_secure_msg_apis.h"
#include "nx_apdu.h"
#include "nx_apdu_tlv.h"
#include "smCom.h"

/** Maximum length (in bytes) of random number data NX SA IC can generate */
#define NX_MAX_RND_DATA_LEN 128

/** Length of BRAINPOOL 256 header */
#define NX_BRAINPOOL_256_HEADER_LEN 27

/** Length of NIST-P (SECP 256 R1) header */
#define NX_NIST_256_HEADER_LEN 26

#define NX_AES128_KEY_LEN (128 / 8)
#define NX_AES256_KEY_LEN (256 / 8)

#if (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
sss_status_t nx_symm_authenticate_channel(pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx);
#endif // SSS_HAVE_AUTH_SYMM_AUTH

#if (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||     \
    (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
sss_status_t nx_sigma_i_authenticate_channel(pSeSession_t seSession, nx_auth_sigma_ctx_t *pAuthCtx);
#endif // SSS_HAVE_AUTH_SIGMA_I_PROVER || SSS_HAVE_AUTH_SIGMA_I_VERIFIER

static SE_ECSignatureAlgo_t nx_get_ec_sign_hash_mode(sss_algorithm_t algorithm);
static smStatus_t sss_nx_channel_txnRaw(void *conn_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended);
static SE_DigestMode_t nx_get_sha_algo(sss_algorithm_t algorithm);
static uint32_t nx_calculate_crc32(const void *pData, size_t length);
static sss_status_t nx_calculate_keydata_with_crc32(const uint8_t *newKeyData,
    size_t newKeyDataLength,
    uint8_t *oldKeyData,
    size_t oldKeyDataLength,
    uint8_t keyVersion,
    uint8_t *keyData,
    size_t *keyDataLen);
static smStatus_t sss_nx_channel_txn(void *conn_ctx,
    nx_auth_type_t currAuth,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended,
    void *options);

#if (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||     \
    (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
    (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) ||               \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
static smStatus_t sss_nx_TXn_AES_EV2(struct SeSession *pSession,
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
#endif // (Any Auth enabled)

static smStatus_t sss_nx_TXn(struct SeSession *pSession,
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
static sss_status_t nx_check_input_len(size_t inLen, sss_algorithm_t algorithm);
static sss_status_t sss_nx_create_policy(sss_policy_t *policy, uint16_t *out_policy);
static Nx_AES_Primitive_t nx_get_aead_primitive(sss_algorithm_t algorithm, sss_mode_t mode);
static sss_status_t nx_aead_one_go_encrypt(sss_nx_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);

static sss_status_t nx_aead_one_go_decrypt(sss_nx_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen);
static sss_status_t nx_aead_encrypt_init(
    sss_nx_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);
static sss_status_t nx_aead_decrypt_init(
    sss_nx_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen);

/*************************** NX SA SSS implementation ***************************/

static sss_status_t sss_nx_create_policy(sss_policy_t *policy, uint16_t *out_policy)
{
    sss_status_t retval = kStatus_SSS_Fail;
    size_t i            = 0;
    uint16_t policybits = 0;

    for (i = 0; i < policy->nPolicies; i++) {
        switch (policy->policies[i]->type) {
        case KPolicy_GenECKey: {
            if (policy->policies[i]->policy.genEcKey.freezeKUCLimit) {
                policybits |= NX_MGMT_KEYPAIR_POLICY_FREEZE_KUCLIMIT;
            }
            if (policy->policies[i]->policy.genEcKey.cardUnilateralEnabled) {
                policybits |= NX_MGMT_KEYPAIR_POLICY_CARD_UNILATERAL;
            }
            if (policy->policies[i]->policy.genEcKey.sdmEnabled) {
                policybits |= NX_MGMT_KEYPAIR_POLICY_SDM_ENABLED;
            }
            if (policy->policies[i]->policy.genEcKey.eccSignEnabled) {
                policybits |= NX_MGMT_KEYPAIR_POLICY_ECC_SIGN_ENABLED;
            }
            if (policy->policies[i]->policy.genEcKey.ecdhEnabled) {
                policybits |= NX_MGMT_KEYPAIR_POLICY_ECDH_ENABLED;
            }
            if (policy->policies[i]->policy.genEcKey.sigmaiEnabled) {
                policybits |= NX_MGMT_KEYPAIR_POLICY_SIGMAI_ENABLED;
            }
        } break;
        default: {
            LOG_E("Unkown policy");
            goto exit;
        }
        }
    }

    retval = kStatus_SSS_Success;
exit:
    *out_policy = policybits;
    return retval;
}

sss_status_t sss_nx_session_open(sss_nx_session_t *session,
    sss_type_t subsystem,
    uint32_t application_id,
    sss_connection_type_t connection_type,
    void *connectionData)
{
    sss_status_t retval        = kStatus_SSS_InvalidArgument;
    nx_connect_ctx_t *pAuthCtx = NULL;
    SmCommState_t CommState    = {0};
    smStatus_t status          = SM_NOT_OK;
    int sm_connected           = 0;
    U16 lReturn                = ERR_COMM_ERROR;
    pSeSession_t seSession     = {0};

    ENSURE_OR_RETURN_ON_ERROR(session, kStatus_SSS_Fail);

    seSession = &session->s_ctx;

    if (session->subsystem != kType_SSS_SubSystem_NONE) {
        LOG_E("Session is not empty. Please confirm if session is reopened");
        retval = kStatus_SSS_Fail;
        goto exit;
    }

    memset(session, 0, sizeof(*session));

    ENSURE_OR_GO_EXIT(NULL != connectionData);
    pAuthCtx = (NX_Connect_Ctx_t *)connectionData;

    if ((pAuthCtx->connType != kType_SE_Conn_Type_Channel) &&
        ((pAuthCtx->auth.authType != knx_AuthType_SYMM_AUTH) ||
            (pAuthCtx->auth.ctx.symmAuth.dyn_ctx.authStatus != kVCState_AuthenticatedAES))) {
        uint8_t cip[100]   = {0};
        uint16_t cipLen    = sizeof(cip);
        CommState.connType = pAuthCtx->connType;

        CommState.select = SELECT_APPLICATION;
        if (1 == pAuthCtx->skip_select_file) {
            CommState.select = SELECT_NONE;
        }

#if SSS_HAVE_SMCOM_VCOM || SSS_HAVE_SMCOM_PCSC || SSS_HAVE_SMCOM_JRCP_V1_AM
#if SSS_HAVE_SMCOM_PCSC
        // On simulator, cip[0] is used to indicate if it's AES CCM secure tunneling.
        if ((pAuthCtx->auth.authType == knx_AuthType_SIGMA_I_Verifier) ||
            (pAuthCtx->auth.authType == knx_AuthType_SIGMA_I_Prover)) {
            cip[0] = 0;
            if (pAuthCtx->auth.ctx.sigmai.dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_CCM) {
                cip[0] = 1;
            }
        }
#endif
        lReturn = SM_RjctConnect(&(seSession->conn_ctx), pAuthCtx->portName, &CommState, cip, &cipLen);

        if (lReturn != SW_OK) {
            LOG_E("SM_RjctConnect Failed. Status %04X", lReturn);
            retval = kStatus_SSS_Fail;
            goto exit;
        }
        if (cipLen != 0) {
            LOG_AU8_I(cip, cipLen);
        }
#else
        /* AX_EMBEDDED Or Native */
        lReturn = SM_I2CConnect(&(seSession->conn_ctx), &CommState, cip, &cipLen, pAuthCtx->portName);
        if (lReturn != SW_OK) {
            LOG_E("SM_I2CConnect Failed. Status %04X", lReturn);
            retval = kStatus_SSS_Fail;
            goto exit;
        }
        if (cipLen != 0) {
            LOG_AU8_I(cip, cipLen);
        }
#endif
        sm_connected = 1;
    }
    else if ((pAuthCtx->connType == kType_SE_Conn_Type_VCOM) || (pAuthCtx->connType == kType_SE_Conn_Type_T1oI2C) ||
             (pAuthCtx->connType == kType_SE_Conn_Type_PCSC) || (pAuthCtx->connType == kType_SE_Conn_Type_JRCP_V1_AM)) {
        seSession->conn_ctx = pAuthCtx->conn_ctx;
        sm_connected        = 1;
    }

    seSession->userCryptoCommMode = Nx_CommMode_NA; // Init user crypto request commMode.

    seSession->fp_TXn    = &sss_nx_TXn;
    seSession->fp_RawTXn = &sss_nx_channel_txn;

    if ((pAuthCtx->auth.authType == knx_AuthType_None) && (connection_type == kSSS_ConnectionType_Plain)) {
#if (defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
        LOG_W("Communication channel is Plain.");
        LOG_W("!!!Security and privacy must be assessed.!!!");
        seSession->fp_Transform = &nx_Transform;
        seSession->fp_DeCrypt   = &nx_DeCrypt;
        seSession->authType     = knx_AuthType_None;
#if SSS_HAVE_SMCOM_JRCP_V1_AM
        seSession->fp_Transform = &nx_Transform_jrcpv1_am;
#endif
        status = SM_OK;
#else
        LOG_E("Wrong Authentication option selected. Rebuild the library with correct AUTH option");
        return kStatus_SSS_Fail;
#endif
    }
    else if (pAuthCtx->auth.authType == knx_AuthType_SIGMA_I_Verifier) {
#if (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
        seSession->fp_Transform = &nx_Transform;
        seSession->fp_DeCrypt   = &nx_DeCrypt;
        seSession->authType     = knx_AuthType_SIGMA_I_Verifier;
        status                  = SM_NOT_OK;

        retval = nx_sigma_i_authenticate_channel(seSession, &pAuthCtx->auth.ctx.sigmai);
        if (retval == kStatus_SSS_Success) {
            seSession->ctx.pdynSigICtx = &(pAuthCtx->auth.ctx.sigmai.dyn_ctx);
            status                     = SM_OK;
            if ((pAuthCtx->auth.ctx.sigmai.dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES128_NTAG) ||
                (pAuthCtx->auth.ctx.sigmai.dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG)) {
                seSession->fp_TXn       = &sss_nx_TXn_AES_EV2;
                seSession->fp_Transform = &nx_Transform_AES_EV2;
            }
            else {
                LOG_E("fp_Transform not defined");
            }
        }
        else {
            LOG_E("Could not set SIGMA-I Verifier Secure Channel");
        }
#else
        LOG_E("Wrong Authentication option selected. Rebuild the library with correct AUTH option");
        return kStatus_SSS_Fail;
#endif
    }
    else if (pAuthCtx->auth.authType == knx_AuthType_SIGMA_I_Prover) {
#if defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
        seSession->fp_Transform = &nx_Transform;
        seSession->fp_DeCrypt   = &nx_DeCrypt;

        seSession->authType = knx_AuthType_SIGMA_I_Prover;
        status              = SM_NOT_OK;
        retval              = nx_sigma_i_authenticate_channel(seSession, &pAuthCtx->auth.ctx.sigmai);
        if (retval == kStatus_SSS_Success) {
            seSession->ctx.pdynSigICtx = &(pAuthCtx->auth.ctx.sigmai.dyn_ctx);
            status                     = SM_OK;
            if ((pAuthCtx->auth.ctx.sigmai.dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES128_NTAG) ||
                (pAuthCtx->auth.ctx.sigmai.dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG)) {
                seSession->fp_TXn       = &sss_nx_TXn_AES_EV2;
                seSession->fp_Transform = &nx_Transform_AES_EV2;
            }
            else {
                LOG_E("fp_Transform not defined");
            }
        }
        else {
            LOG_E("Could not set SIGMA-I Prover Secure Channel");
        }
#else
        LOG_E("Wrong Authentication option selected. Rebuild the library with correct AUTH option");
        return kStatus_SSS_Fail;
#endif
    }
    else if (pAuthCtx->auth.authType == knx_AuthType_SYMM_AUTH) {
#if (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
        seSession->fp_Transform = &nx_Transform;
        seSession->fp_DeCrypt   = &nx_DeCrypt;
        seSession->authType     = knx_AuthType_SYMM_AUTH;
        status                  = SM_NOT_OK;
        retval                  = nx_symm_authenticate_channel(seSession, &pAuthCtx->auth.ctx.symmAuth);
        if (retval == kStatus_SSS_Success) {
            seSession->ctx.pdynSymmAuthCtx = &(pAuthCtx->auth.ctx.symmAuth.dyn_ctx);
            status                         = SM_OK;
            seSession->fp_TXn              = &sss_nx_TXn_AES_EV2;
            seSession->fp_Transform        = &nx_Transform_AES_EV2;
        }
        else {
            LOG_E("Could not set Symmetric Auth Secure Channel");
        }
#else
        LOG_E("Wrong Authentication option selected. Rebuild the library with correct AUTH option");
        return kStatus_SSS_Fail;
#endif
    }
    else {
        LOG_E("Invalid AUth option");
        status = SM_NOT_OK;
    }

    if (status == SM_OK) {
        session->subsystem = subsystem;
        retval             = kStatus_SSS_Success;
    }
    else {
        retval = kStatus_SSS_Fail;
    }
exit:
    if (retval != kStatus_SSS_Success) {
        if ((sm_connected) && (pAuthCtx->connType != kType_SE_Conn_Type_Channel)) {
            SM_Close(seSession->conn_ctx, 0);
        }

        memset(session, 0x00, sizeof(*session));
    }
    else {
        LOG_I("Session Open Succeed");
    }

    return retval;
}

sss_status_t sss_nx_session_close(sss_nx_session_t *session)
{
    if (session->subsystem == kType_SSS_SubSystem_NONE) {
        LOG_E("Fail to close session. It may have already been closed.");
        return kStatus_SSS_Fail;
    }

    SM_Close(session->s_ctx.conn_ctx, 0);

    memset(session, 0, sizeof(*session));

    return kStatus_SSS_Success;
}

bool sss_nx_check_slot_num_valid(uint8_t slotNum)
{
    if (slotNum >= kSE_CryptoDataSrc_TB0 && slotNum <= kSE_CryptoDataSrc_TB7) {
        // Transisent buffers
        return true;
    }
    else if (slotNum >= kSE_CryptoDataSrc_SB0 && slotNum <= kSE_CryptoDataSrc_SBF) {
        // Static buffers
        return true;
    }
    else {
        // Invalid slot number
        return false;
    }
}

sss_status_t sss_nx_key_store_context_init(sss_nx_key_store_t *keyStore, sss_nx_session_t *session)
{
    sss_status_t retval = kStatus_SSS_Success;
    if (keyStore == NULL) {
        return kStatus_SSS_Fail;
    }
    memset(keyStore, 0, sizeof(*keyStore));
    keyStore->session = session;
    return retval;
}

sss_status_t sss_nx_key_store_allocate(sss_nx_key_store_t *keyStore, uint32_t keyStoreId)
{
    AX_UNUSED_ARG(keyStore);
    AX_UNUSED_ARG(keyStoreId);
    return kStatus_SSS_Success;
}

uint32_t nx_sssKeyTypeLenToCurveId(sss_cipher_type_t cipherType, size_t keyBits)
{
    uint32_t u32_curve_id = Nx_ECCurve_NA;
    switch (cipherType) {
    case kSSS_CipherType_EC_NIST_P:
    case kSSS_CipherType_CARootKeys_NIST_P: {
        Nx_ECCurve_t eCurveID = Nx_ECCurve_NA;
        switch (keyBits) {
        case 256:
            eCurveID = Nx_ECCurve_NIST_P256;
            break;
        default:
            eCurveID = Nx_ECCurve_NA;
        }
        u32_curve_id = (uint32_t)eCurveID;
        break;
    }
    case kSSS_CipherType_EC_BRAINPOOL:
    case kSSS_CipherType_CARootKeys_BRAINPOOL: {
        Nx_ECCurve_t eCurveID = Nx_ECCurve_NA;
        switch (keyBits) {
        case 256:
            eCurveID = Nx_ECCurve_Brainpool256;
            break;
        default:
            eCurveID = Nx_ECCurve_NA;
        }
        u32_curve_id = (uint32_t)eCurveID;
        break;
    }
    default:
        break;
    }
    return u32_curve_id;
}

sss_status_t sss_nx_key_store_set_key(sss_nx_key_store_t *keyStore,
    sss_nx_object_t *keyObject,
    const uint8_t *key,
    size_t keyLen,
    size_t keyBitLen,
    void *options,
    size_t optionsLen)
{
    sss_status_t retval           = kStatus_SSS_Fail;
    smStatus_t status             = SM_NOT_OK;
    sss_cipher_type_t cipher_type = kSSS_CipherType_NONE;
    Nx_CommMode_t writeCommMode   = 0;
    uint8_t writeAccessCond       = 0;
    uint32_t kucLimit             = 0;
    Nx_CommMode_t userCommMode    = 0;
    sss_policy_t *policy          = NULL;
    uint16_t nx_policy            = 0;

    ENSURE_OR_GO_EXIT(NULL != keyStore);
    ENSURE_OR_GO_EXIT(NULL != keyObject);
    ENSURE_OR_GO_EXIT(NULL != key);

    cipher_type = (sss_cipher_type_t)keyObject->cipherType;
    policy      = (sss_policy_t *)options;

    switch (cipher_type) {
    case kSSS_CipherType_CARootKeys_NIST_P:
    case kSSS_CipherType_CARootKeys_BRAINPOOL: {
        sss_policy_u *rootKeyPolicy;
        uint8_t tmpCommMode;

        ENSURE_OR_GO_EXIT(NULL != options);
        ENSURE_OR_GO_EXIT(policy->nPolicies == 1);
        rootKeyPolicy = (sss_policy_u *)(policy->policies[0]);
        ENSURE_OR_GO_EXIT(NULL != rootKeyPolicy);
        ENSURE_OR_GO_EXIT(rootKeyPolicy->type == KPolicy_UpdateCARootKey);

        if (keyObject->curve_id == Nx_ECCurve_NA) {
            keyObject->curve_id =
                (Nx_ECCurve_t)nx_sssKeyTypeLenToCurveId((sss_cipher_type_t)keyObject->cipherType, keyBitLen);
        }
        if (keyObject->curve_id == Nx_ECCurve_NA) {
            goto exit;
        }

        if (rootKeyPolicy->policy.updCARootKey.issuerLen > 0xFF) {
            LOG_E("Invalid issuer length");
            goto exit;
        }

        // writeCommMode: 00b-11b, writeAccessCond: 0x0-0xF
        if (((rootKeyPolicy->policy.updCARootKey.writeCommMode & 0xFC) != 0) ||
            ((rootKeyPolicy->policy.updCARootKey.writeAccessCond & 0xF0) != 0)) {
            LOG_E("Invalid write access right");
            goto exit;
        }

        tmpCommMode = rootKeyPolicy->policy.updCARootKey.writeCommMode;
        if ((tmpCommMode != Nx_CommMode_Plain) && (tmpCommMode != Nx_CommMode_MAC) &&
            (tmpCommMode != Nx_CommMode_FULL)) {
            LOG_E("Invalid Write CommMode");
            goto exit;
        }
        else {
            writeCommMode = tmpCommMode;
        }

        ENSURE_OR_GO_EXIT(keyObject->keyId <= UINT8_MAX);
        status = nx_ManageCARootKey(&keyStore->session->s_ctx,
            keyObject->keyId,
            keyObject->curve_id,
            rootKeyPolicy->policy.updCARootKey.acBitmap,
            writeCommMode,
            rootKeyPolicy->policy.updCARootKey.writeAccessCond,
            (uint8_t *)key,
            keyLen,
            rootKeyPolicy->policy.updCARootKey.issuer,
            (uint8_t)(rootKeyPolicy->policy.updCARootKey.issuerLen),
            rootKeyPolicy->policy.updCARootKey.userCommMode);
        if (status != SM_OK) {
            goto exit;
        }

        break;
    }
    case kSSS_CipherType_EC_NIST_P:
    case kSSS_CipherType_EC_BRAINPOOL: {
        // Don't need to call SE API for ephemeral keys
        if ((keyObject->keyId == NX_KEY_ID_EPHEM_NISTP256) || (keyObject->keyId == NX_KEY_ID_EPHEM_BP256)) {
            LOG_W("Keyid's %d and %d are used for ephemeral keys.", NX_KEY_ID_EPHEM_NISTP256, NX_KEY_ID_EPHEM_BP256);
            LOG_W("Cannot be used for set key api");
            goto exit;
        }

        if (keyObject->objectType == kSSS_KeyPart_Public) {
            // Store public key will be stored in keyObject buffer.
            ENSURE_OR_GO_EXIT(keyLen <= sizeof(keyObject->pubKey));
            memcpy(keyObject->pubKey, key, keyLen);
            keyObject->pubKeyLen = keyLen;
            retval               = kStatus_SSS_Success;
            goto exit;
        }

        if ((NULL != policy) && (policy->nPolicies >= 1)) {
            uint8_t tmpCommMode = Nx_CommMode_NA;

            ENSURE_OR_GO_EXIT(sss_nx_create_policy(policy, &nx_policy) == kStatus_SSS_Success);

            tmpCommMode = policy->policies[0]->policy.genEcKey.writeCommMode;
            if ((tmpCommMode != Nx_CommMode_Plain) && (tmpCommMode != Nx_CommMode_MAC) &&
                (tmpCommMode != Nx_CommMode_FULL)) {
                LOG_E("Invalid Write CommMode");
                goto exit;
            }
            else {
                writeCommMode = tmpCommMode;
            }
            writeAccessCond = policy->policies[0]->policy.genEcKey.writeAccessCond;
            kucLimit        = policy->policies[0]->policy.genEcKey.kucLimit;
            userCommMode    = policy->policies[0]->policy.genEcKey.userCommMode;
        }
        else {
            LOG_W("No Policy passed. Use default policy.");
            nx_policy       = NX_MGMT_KEYPAIR_POLICY_ECC_SIGN_ENABLED;
            writeCommMode   = Nx_CommMode_FULL;
            writeAccessCond = Nx_AccessCondition_Auth_Required_0x0;
            kucLimit        = 0x00;
            userCommMode    = Nx_CommMode_NA;
        }

        if (keyObject->curve_id == Nx_ECCurve_NA) {
            keyObject->curve_id =
                (Nx_ECCurve_t)nx_sssKeyTypeLenToCurveId((sss_cipher_type_t)keyObject->cipherType, keyBitLen);
        }
        if (keyObject->curve_id == Nx_ECCurve_NA) {
            goto exit;
        }

        status = nx_ManageKeyPair(&keyStore->session->s_ctx,
            keyObject->keyId,
            Nx_MgtKeyPair_Act_Import_SK,
            keyObject->curve_id,
            nx_policy,
            writeCommMode,
            writeAccessCond,
            kucLimit,
            (uint8_t *)key,
            keyLen,
            NULL,
            NULL,
            userCommMode);
        ENSURE_OR_GO_EXIT(status == SM_OK);
        break;
    }

    case kSSS_CipherType_AES: {
        NX_KEY_TYPE_t keyType                     = NX_KEY_TYPE_NA;
        uint16_t symmKeyPolicy                    = 0;
        uint8_t keyTmp[NX_AES256_KEY_LEN + 1 + 4] = {0}; // (NewKey XOR OldKey) || KeyVer || CRC32NK
        size_t keyTmpLen                          = sizeof(keyTmp);
        SeSession_t *pSession                     = NULL;
        sss_policy_chgAesKey_u *param             = NULL;

        ENSURE_OR_GO_EXIT((keyLen == NX_AES128_KEY_LEN) || (keyLen == NX_AES256_KEY_LEN));
        ENSURE_OR_GO_EXIT(policy != NULL);
        ENSURE_OR_GO_EXIT(policy->policies[0] != NULL);

        param    = (sss_policy_chgAesKey_u *)&(policy->policies[0]->policy.chgAesKey);
        pSession = &keyStore->session->s_ctx;

        if (keyObject->keyId == NX_KEY_MGMT_MIN_APP_KEY_NUMBER) {
            if ((pSession->authType == knx_AuthType_SIGMA_I_Verifier) ||
                (pSession->authType == knx_AuthType_SIGMA_I_Prover)) {
                retval = nx_calculate_keydata_with_crc32(
                    key, keyLen, param->oldKey, param->oldKeyLen, param->keyVersion, keyTmp, &keyTmpLen);
                ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);
                retval = kStatus_SSS_Fail;
            }
            else if (pSession->authType == knx_AuthType_SYMM_AUTH) {
                memcpy(keyTmp, key, keyLen);
                keyTmp[keyLen] = param->keyVersion; /* Version info */
                keyTmpLen      = keyLen + 1;        // Version
            }
            else {
                LOG_I("Invalid access condition for change symm key.");
                goto exit;
            }
        }
        else if ((keyObject->keyId > NX_KEY_MGMT_MIN_APP_KEY_NUMBER) &&
                 (keyObject->keyId <= NX_KEY_MGMT_MAX_APP_KEY_NUMBER)) {
            if ((pSession->authType == knx_AuthType_SIGMA_I_Verifier) ||
                (pSession->authType == knx_AuthType_SIGMA_I_Prover) || (pSession->authType == knx_AuthType_SYMM_AUTH)) {
                retval = nx_calculate_keydata_with_crc32(
                    key, keyLen, param->oldKey, param->oldKeyLen, param->keyVersion, keyTmp, &keyTmpLen);
                ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);
                retval = kStatus_SSS_Fail;
            }
            else {
                LOG_I("Invalid access condition for change symm key.");
                goto exit;
            }
        }
        else if ((keyObject->keyId >= NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) &&
                 (keyObject->keyId <= NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER)) {
            bool isHMACKey = false, isAESKey = false;

            memcpy(keyTmp, key, keyLen);
            keyTmp[keyLen] = param->keyVersion; /* Version info */
            keyTmpLen      = keyLen + 1;        // Version

            if ((param->hkdfEnabled) || (param->hmacEnabled)) {
                isHMACKey = true;
            }
            if ((param->aeadEncIntEnabled) || (param->aeadEncEnabled) || (param->aeadDecEnabled) ||
                (param->ecb_cbc_EncEnabled) || (param->ecb_cbc_DecEnabled) || (param->macSignEnabled) ||
                (param->macVerifyEnabled)) {
                isAESKey = true;
            }
            if ((isHMACKey) && (isAESKey)) {
                LOG_E("Not support HMAC/HKDF key with AES Key at the same time!");
                goto exit;
            }

            if (param->hkdfEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_HKDF_ENABLED;
            }
            if (param->hmacEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_HMAC_ENABLED;
            }
            if (param->aeadEncIntEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_AEAD_ENC_INTERANL_NONCE_ENABLED;
            }
            if (param->aeadEncEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_AEAD_ENC_ENABLED;
            }
            if (param->aeadDecEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_AEAD_DEC_ENABLED;
            }
            if (param->ecb_cbc_EncEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_ECB_CBC_ENC_ENABLED;
            }
            if (param->ecb_cbc_DecEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_ECB_CBC_DEC_ENABLED;
            }
            if (param->macSignEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_MAC_SIGN_ENABLED;
            }
            if (param->macVerifyEnabled) {
                symmKeyPolicy |= NX_MGMT_KEYPAIR_POLICY_MAC_VERIFY_ENABLED;
            }
        }
        else {
            LOG_E("Invalid Symm Key ID 0x%x!", keyObject->keyId);
            goto exit;
        }

        if (keyLen == NX_AES128_KEY_LEN) {
            keyType = NX_KEY_TYPE_AES128;
        }
        else {
            keyType = NX_KEY_TYPE_AES256;
        }

        status = nx_ChangeKey(
            &keyStore->session->s_ctx, keyObject->keyId, keyType, symmKeyPolicy, (uint8_t *)keyTmp, keyTmpLen);
        if (status != SM_OK) {
            goto exit;
        }
        break;
    }
    case kSSS_CipherType_BufferSlots: {
        if (((keyObject->keyId >= kSE_CryptoAESKey_TB_SLOTNUM_MIN) &&
                (keyObject->keyId <= kSE_CryptoAESKey_TB_SLOTNUM_MAX)) ||
            ((keyObject->keyId >= kSE_CryptoAESKey_SB_SLOTNUM_MIN) &&
                (keyObject->keyId <= kSE_CryptoAESKey_SB_SLOTNUM_MAX))) {
            status = nx_CryptoRequest_Write_Internal_Buffer(&keyStore->session->s_ctx, keyObject->keyId, key, keyLen);
            if (status != SM_OK) {
                LOG_E("Write internal buffer failed!");
                goto exit;
            }
            keyObject->keyLen = (uint8_t)keyLen;
        }
        else {
            LOG_E("Invalid Internal Buffer Slot Number!");
            goto exit;
        }
        break;
    }
    default:
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_key_store_generate_key(
    sss_nx_key_store_t *keyStore, sss_nx_object_t *keyObject, size_t keyBitLen, void *options)
{
    sss_status_t retval         = kStatus_SSS_Fail;
    smStatus_t status           = SM_NOT_OK;
    sss_policy_t *policy        = (sss_policy_t *)options;
    uint16_t nx_policy          = 0;
    Nx_MgtKeyPair_Act_t option  = Nx_MgtKeyPair_Act_Generate_Keypair;
    Nx_CommMode_t writeCommMode = 0;
    uint8_t writeAccessCond     = 0;
    uint32_t kucLimit           = 0;
    Nx_CommMode_t userCommMode  = 0;
    size_t pubKeyBufLen         = 0;

    ENSURE_OR_GO_EXIT(NULL != keyStore);
    ENSURE_OR_GO_EXIT(NULL != keyObject);
    ENSURE_OR_GO_EXIT(keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
                      keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL); // Should only generate ECC Keypair.

    // Don't need to call SE API for ephemeral keys
    if ((keyObject->keyId == NX_KEY_ID_EPHEM_NISTP256) || (keyObject->keyId == NX_KEY_ID_EPHEM_BP256)) {
        LOG_W("Keyid's %d and %d are used for ephemeral keys.", NX_KEY_ID_EPHEM_NISTP256, NX_KEY_ID_EPHEM_BP256);
        LOG_W("Key is already present at these locations. No new key is created");
        retval = kStatus_SSS_Success;
        goto exit;
    }

    if ((NULL != policy) && (policy->nPolicies >= 1)) {
        uint8_t tmpCommMode = Nx_CommMode_NA;

        ENSURE_OR_GO_EXIT(sss_nx_create_policy(policy, &nx_policy) == kStatus_SSS_Success);

        tmpCommMode = policy->policies[0]->policy.genEcKey.writeCommMode;
        if ((tmpCommMode != Nx_CommMode_Plain) && (tmpCommMode != Nx_CommMode_MAC) &&
            (tmpCommMode != Nx_CommMode_FULL)) {
            LOG_E("Invalid Write CommMode");
            goto exit;
        }
        else {
            writeCommMode = policy->policies[0]->policy.genEcKey.writeCommMode;
        }
        writeAccessCond = policy->policies[0]->policy.genEcKey.writeAccessCond;
        kucLimit        = policy->policies[0]->policy.genEcKey.kucLimit;
        userCommMode    = policy->policies[0]->policy.genEcKey.userCommMode;
    }
    else {
        LOG_W("No Policy passed. Use default policy.");
        nx_policy       = NX_MGMT_KEYPAIR_POLICY_ECC_SIGN_ENABLED;
        writeCommMode   = Nx_CommMode_FULL;
        writeAccessCond = Nx_AccessCondition_Auth_Required_0x0;
        kucLimit        = 0x00;
        userCommMode    = Nx_CommMode_NA;
    }

    switch (keyObject->cipherType) {
    case kSSS_CipherType_EC_NIST_P:
    case kSSS_CipherType_EC_BRAINPOOL: {
        if (keyObject->curve_id == Nx_ECCurve_NA) {
            keyObject->curve_id =
                (Nx_ECCurve_t)nx_sssKeyTypeLenToCurveId((sss_cipher_type_t)keyObject->cipherType, keyBitLen);
        }
        if (keyObject->curve_id == Nx_ECCurve_NA) {
            goto exit;
        }

        // Add header to key
        if (keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
            ENSURE_OR_GO_EXIT(sizeof(keyObject->pubKey) > der_ecc_nistp256_header_len);
            memcpy(keyObject->pubKey, gecc_der_header_nist256, der_ecc_nistp256_header_len);
            keyObject->pubKeyLen = der_ecc_nistp256_header_len;
        }
        else {
            ENSURE_OR_GO_EXIT(sizeof(keyObject->pubKey) > der_ecc_bp256_header_len);
            memcpy(keyObject->pubKey, gecc_der_header_bp256, der_ecc_bp256_header_len);
            keyObject->pubKeyLen = der_ecc_bp256_header_len;
        }

        pubKeyBufLen = sizeof(keyObject->pubKey) - (keyObject->pubKeyLen);

        status = nx_ManageKeyPair(&keyStore->session->s_ctx,
            keyObject->keyId,
            option,
            keyObject->curve_id,
            nx_policy,
            writeCommMode,
            writeAccessCond,
            kucLimit,
            NULL,
            0,
            (keyObject->pubKey + (keyObject->pubKeyLen)),
            &pubKeyBufLen,
            userCommMode);
        ENSURE_OR_GO_EXIT(status == SM_OK);
        keyObject->pubKeyLen += pubKeyBufLen;
        break;
    }

    default: {
        goto exit;
    }
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_key_store_get_key(
    sss_nx_key_store_t *keyStore, sss_nx_object_t *keyObject, uint8_t *data, size_t *dataLen, size_t *pKeyBitLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(NULL != keyStore);
    ENSURE_OR_GO_EXIT(NULL != keyObject);
    ENSURE_OR_GO_EXIT(NULL != data);

    if (keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL || keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
        ENSURE_OR_GO_EXIT(NULL != dataLen);
        ENSURE_OR_GO_EXIT(*dataLen >= keyObject->pubKeyLen);
        memcpy(data, keyObject->pubKey, keyObject->pubKeyLen);
        *dataLen = keyObject->pubKeyLen;
    }
    else {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_nx_key_store_context_free(sss_nx_key_store_t *keyStore)
{
    if (NULL == keyStore) {
        LOG_E("No keyStore to free!");
    }
    else {
        memset(keyStore, 0, sizeof(*keyStore));
    }
}

sss_status_t sss_nx_key_object_init(sss_nx_object_t *keyObject, sss_nx_key_store_t *keyStore)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(NULL != keyObject);
    ENSURE_OR_GO_EXIT(NULL != keyStore);
    memset(keyObject, 0, sizeof(*keyObject));
    keyObject->keyStore = (sss_key_store_t *)keyStore;
    retval              = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_key_object_allocate_handle(sss_nx_object_t *keyObject,
    uint32_t keyId,
    sss_key_part_t key_part,
    sss_cipher_type_t cipherType,
    size_t keyByteLenMax,
    uint32_t options)
{
    sss_status_t retval = kStatus_SSS_Fail;

    if (keyObject == NULL) {
        goto exit;
    }

    keyObject->cipherType = cipherType;
    keyObject->objectType = key_part;
    if (keyId > UINT8_MAX) {
        LOG_E("Key ID exceeds 1 byte!");
        goto exit;
    }
    keyObject->keyId = keyId;

    switch (keyObject->cipherType) {
    case kSSS_CipherType_CARootKeys_BRAINPOOL:
    case kSSS_CipherType_CARootKeys_NIST_P:
    case kSSS_CipherType_EC_BRAINPOOL:
    case kSSS_CipherType_EC_NIST_P: {
        if (keyObject->keyId == NX_KEY_ID_EPHEM_NISTP256 || keyObject->keyId == NX_KEY_ID_EPHEM_BP256) {
            if (options == kKeyObject_Mode_Persistent) {
                LOG_W(
                    "Keyid's %d and %d are used for ephemeral keys.", NX_KEY_ID_EPHEM_NISTP256, NX_KEY_ID_EPHEM_BP256);
                LOG_W("Persistent key option is ignored");
            }
        }

        /* To do - Check valid range */

        if (keyByteLenMax > (UINT_MAX / 8)) {
            goto exit;
        }
        keyObject->curve_id =
            (Nx_ECCurve_t)nx_sssKeyTypeLenToCurveId((sss_cipher_type_t)keyObject->cipherType, (keyByteLenMax * 8));
        break;
    }
    case kSSS_CipherType_AES: {
        if ((keyId >= kSE_CryptoAESKey_TB_SLOTNUM_MIN) && (keyId <= kSE_CryptoAESKey_TB_SLOTNUM_MAX)) {
            if (options != kKeyObject_Mode_Transient) {
                LOG_W("The key mode does not seem to match the nature of buffer you are trying to set the key into");
            }
            else {
                /*Do Nothing, a valid keyId and key_mode*/
            }
        }
        else if ((keyId >= kSE_CryptoAESKey_SB_SLOTNUM_MIN) && (keyId <= kSE_CryptoAESKey_SB_SLOTNUM_MAX)) {
            if (options != kKeyObject_Mode_Persistent) {
                LOG_W("Use static buffer as indicated by keyId (slot number)");
            }
            else {
                /*Do Nothing, a valid keyId and key_mode*/
            }
        }
        else if ((keyId >= NX_KEY_MGMT_MIN_CRYPTO_KEY_NUMBER) && (keyId <= NX_KEY_MGMT_MAX_CRYPTO_KEY_NUMBER)) {
            /*Do Nothing, a valid keyID for a Crypto Key*/
        }
        else if (/*(keyId >= NX_KEY_MGMT_MIN_APP_KEY_NUMBER) &&*/ keyId <= NX_KEY_MGMT_MAX_APP_KEY_NUMBER) {
            /*Do Nothing, a valid keyID for an App Key*/
        }
        else {
            LOG_E("Invalid keyId");
            goto exit;
        }
    } break;
    case kSSS_CipherType_BufferSlots: {
        if (true != sss_nx_check_slot_num_valid(keyObject->keyId)) {
            LOG_E("Invalid id for Buffer slots");
            LOG_E("Valid range: Transient buffer slots - 0x80 to 0x87. Static buffer slots - 0xC0 to 0xCF ");
            goto exit;
        }
        if ((options == kKeyObject_Mode_Persistent) || (options == kKeyObject_Mode_Transient)) {
            LOG_W("Keyid %d indicate Persistent/Transient key", keyObject->keyId);
            LOG_W("Persistent/Transient key option is ignored");
        }
    } break;

    default:
        goto exit;
    }
    retval = kStatus_SSS_Success;

exit:
    return retval;
}

sss_status_t sss_nx_key_object_get_handle(sss_nx_object_t *keyObject, sss_cipher_type_t cipherType, uint32_t keyId)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    uint8_t entryCount           = 0;
    int keyIndex                 = -1;
    sss_nx_key_store_t *keyStore = NULL;
    ENSURE_OR_GO_EXIT(NULL != keyObject);

    keyStore = (sss_nx_key_store_t *)(keyObject->keyStore);
    nx_crypto_key_meta_data_t cryptoRequestKeyList[NX_KEY_SETTING_CRYPTO_KEY_MAX_ENTRY] = {0};
    nx_ecc_key_meta_data_t eccPrivateKeyList[NX_KEY_SETTING_ECC_KEY_MAX_ENTRY]          = {0};
    nx_ca_root_key_meta_data_t caRootKeyList[NX_KEY_SETTING_CAROOTKEY_MAX_ENTRY]        = {0};

    ENSURE_OR_GO_EXIT(NULL != keyStore);
    ENSURE_OR_GO_EXIT(NULL != keyStore->session);
    switch (cipherType) {
    case kSSS_CipherType_AES:
        entryCount = NX_KEY_SETTING_CRYPTO_KEY_MAX_ENTRY;
        status = nx_GetKeySettings_CryptoRequestKeyList(&keyStore->session->s_ctx, &entryCount, cryptoRequestKeyList);
        ENSURE_OR_GO_EXIT(status == SM_OK);

        for (uint8_t i = 0; i < entryCount; i++) {
            if (keyId == cryptoRequestKeyList[i].keyId) {
                keyIndex = i;
                break;
            }
        }
        if (keyIndex < 0) {
            LOG_E("Key with ID %d does not exist! line: %d", keyId, __LINE__);
            goto exit;
        }
        keyObject->keyId      = keyId;
        keyObject->objectType = kSSS_KeyPart_Default;
        keyObject->cipherType = cipherType;
        memset(cryptoRequestKeyList, 0, sizeof(cryptoRequestKeyList));
        break;
    case kSSS_CipherType_EC_NIST_P:
    case kSSS_CipherType_EC_BRAINPOOL:

        if ((keyId == NX_KEY_ID_EPHEM_NISTP256) || (keyId == NX_KEY_ID_EPHEM_BP256)) {
            /* Ephemeral keys */
            keyObject->keyId    = keyId;
            keyObject->curve_id = (keyId == NX_KEY_ID_EPHEM_NISTP256) ? Nx_ECCurve_NIST_P256 : Nx_ECCurve_Brainpool256;
            keyObject->objectType = kSSS_KeyPart_Private;
            keyObject->cipherType = (keyObject->curve_id == Nx_ECCurve_NIST_P256) ? kSSS_CipherType_EC_NIST_P :
                                                                                    kSSS_CipherType_EC_BRAINPOOL;
        }
        else {
            entryCount = NX_KEY_SETTING_ECC_KEY_MAX_ENTRY;
            status     = nx_GetKeySettings_ECCPrivateKeyList(&keyStore->session->s_ctx, &entryCount, eccPrivateKeyList);
            ENSURE_OR_GO_EXIT(status == SM_OK);

            for (uint8_t i = 0; i < entryCount; i++) {
                if (keyId == eccPrivateKeyList[i].keyId) {
                    keyIndex = i;
                    break;
                }
            }
            if (keyIndex < 0) {
                LOG_E("Key with ID %d does not exist! line: %d", keyId, __LINE__);
                goto exit;
            }

            keyObject->keyId    = keyId;
            keyObject->curve_id = eccPrivateKeyList[keyIndex].curveId;
            if (keyObject->curve_id == Nx_ECCurve_NA) {
                LOG_E("Invalid Curve ID");
                goto exit;
            }
            keyObject->objectType = kSSS_KeyPart_Private;
            keyObject->cipherType = (keyObject->curve_id == Nx_ECCurve_NIST_P256) ? kSSS_CipherType_EC_NIST_P :
                                                                                    kSSS_CipherType_EC_BRAINPOOL;
            memset(eccPrivateKeyList, 0, sizeof(eccPrivateKeyList));
        }
        break;
    case kSSS_CipherType_CARootKeys_NIST_P:
    case kSSS_CipherType_CARootKeys_BRAINPOOL:
        entryCount = NX_KEY_SETTING_CAROOTKEY_MAX_ENTRY;
        status     = nx_GetKeySettings_CARootKeyList(&keyStore->session->s_ctx, &entryCount, caRootKeyList);
        ENSURE_OR_GO_EXIT(status == SM_OK);

        for (uint8_t i = 0; i < entryCount; i++) {
            if (keyId == caRootKeyList[i].keyId) {
                keyIndex = i;
                break;
            }
        }
        if (keyIndex < 0) {
            LOG_E("Key with ID %d does not exist! line: %d", keyId, __LINE__);
            goto exit;
        }

        keyObject->keyId    = keyId;
        keyObject->curve_id = caRootKeyList[keyIndex].curveId;
        if (keyObject->curve_id == Nx_ECCurve_NA) {
            LOG_E("Invalid Curve ID");
            goto exit;
        }
        keyObject->objectType = kSSS_KeyPart_Public;
        keyObject->cipherType = (keyObject->curve_id == Nx_ECCurve_NIST_P256) ? kSSS_CipherType_CARootKeys_NIST_P :
                                                                                kSSS_CipherType_CARootKeys_BRAINPOOL;
        memset(caRootKeyList, 0, sizeof(caRootKeyList));
        break;
    default:
        LOG_E("Invalid curve type!");
        goto exit;
    }
    retval = kStatus_SSS_Success;

exit:
    return retval;
}

void sss_nx_key_object_free(sss_nx_object_t *keyObject)
{
    if (NULL == keyObject) {
        LOG_E("No keyObject to free!");
    }
    else {
        memset(keyObject, 0, sizeof(*keyObject));
    }
}

sss_status_t sss_nx_asymmetric_context_init(sss_nx_asymmetric_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(NULL != context)
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;

    retval = kStatus_SSS_Success;

exit:
    return retval;
}

/* sss_util_encode_asn1_signature will handle signature of only Nist256 and BP256 for now */
sss_status_t sss_util_encode_asn1_signature(
    uint8_t *signatureAsn1, size_t *signatureLenAsn1, uint8_t *rawSignature, size_t rawSignatureLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t offset       = 0;

    ENSURE_OR_GO_EXIT(signatureAsn1 != NULL);
    ENSURE_OR_GO_EXIT(signatureLenAsn1 != NULL);
    ENSURE_OR_GO_EXIT(rawSignature != NULL);
    ENSURE_OR_GO_EXIT(rawSignatureLen == NX_RAW_SIGNATURE_LENGTH);

    /* ASN! format - 0x30|Rem len|0x02|r_len|r|0x02|s_len|s */

    signatureAsn1[0] = 0x30;
    signatureAsn1[1] = (uint8_t)(rawSignatureLen + 2 /* Tag + len */ + 2 /* Tag + len */);

    /* Update R value*/
    signatureAsn1[2] = 0x02;
    signatureAsn1[3] = (uint8_t)32;
    if ((rawSignature[0] & 0x80) == 0x80) /* Check for first byte of R */
    {
        signatureAsn1[1]++;
        signatureAsn1[3]++;
        signatureAsn1[4] = 0x00;
        memcpy(&signatureAsn1[5], &rawSignature[0], 32);
        offset = 5 + 32;
    }
    else {
        memcpy(&signatureAsn1[4], &rawSignature[0], 32);
        offset = 4 + 32;
    }

    *signatureLenAsn1 = offset;

    /* Update S value*/
    signatureAsn1[offset + 0] = 0x02;
    signatureAsn1[offset + 1] = (uint8_t)32;
    if ((rawSignature[32] & 0x80) == 0x80) /* Check for first byte of S */
    {
        signatureAsn1[1]++;
        signatureAsn1[offset + 1]++;
        signatureAsn1[offset + 2] = 0x00;
        memcpy(&signatureAsn1[offset + 3], &rawSignature[32], 32);
        *signatureLenAsn1 += 3 + 32;
    }
    else {
        memcpy(&signatureAsn1[offset + 2], &rawSignature[32], 32);
        *signatureLenAsn1 += 2 + 32;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}
sss_status_t sss_nx_asymmetric_sign_digest(
    sss_nx_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t *signatureLen)
{
    sss_status_t retval                            = kStatus_SSS_Fail;
    smStatus_t status                              = SM_NOT_OK;
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {
        0,
    };
    size_t raw_signatureLen = sizeof(raw_signature);

    ENSURE_OR_GO_EXIT(digest != NULL);
    ENSURE_OR_GO_EXIT(context != NULL);
    ENSURE_OR_GO_EXIT(context->keyObject != NULL);
    ENSURE_OR_GO_EXIT(signature != NULL);
    ENSURE_OR_GO_EXIT(signatureLen != NULL);
    ENSURE_OR_GO_EXIT(context->keyObject->keyId <= UINT8_MAX);

    if (kStatus_SSS_Success != nx_check_input_len(digestLen, context->algorithm)) {
        LOG_E("Algorithm and digest length do not match");
        goto exit;
    }

    if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        SE_ECSignatureAlgo_t ecSignAlgo = nx_get_ec_sign_hash_mode(context->algorithm);
        if (ecSignAlgo == kSE_ECSignatureAlgo_NA) {
            LOG_E("Invalid algorithm 0x%x", ecSignAlgo);
            goto exit;
        }

        status = nx_CryptoRequest_ECCSign_Digest_Oneshot(&context->session->s_ctx,
            ecSignAlgo,
            context->keyObject->keyId,
            kSE_CryptoDataSrc_CommandBuf,
            digest,
            digestLen,
            raw_signature,
            &raw_signatureLen);
        ENSURE_OR_GO_EXIT(status == SM_OK);

        ENSURE_OR_GO_EXIT(kStatus_SSS_Success ==
                          sss_util_encode_asn1_signature(signature, signatureLen, raw_signature, raw_signatureLen));
    }
    else {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_util_decode_asn1_signature(
    uint8_t *rawSignature, size_t *rawSignatureLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t *p          = NULL;
    uint8_t *end        = NULL;
    uint8_t *pSigBuf    = NULL;
    size_t len          = 0;
    int ret             = -1;

    ENSURE_OR_GO_EXIT(signature != NULL);
    ENSURE_OR_GO_EXIT(rawSignature != NULL);
    ENSURE_OR_GO_EXIT(rawSignatureLen != NULL);
    ENSURE_OR_GO_EXIT(*rawSignatureLen >= NX_RAW_SIGNATURE_LENGTH);

    p       = signature;
    len     = signatureLen;
    end     = p + signatureLen;
    pSigBuf = rawSignature;

    // SEQ
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
        LOG_E("Signature SEQ error");
        goto exit;
    }

    // INTEGER
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_INTEGER)) != 0) {
        LOG_E("Signature r error");
        goto exit;
    }

    memset(rawSignature, 0, *rawSignatureLen);

    if (len == 0x21) {
        // p -> 00 [r]
        ENSURE_OR_GO_EXIT(len == 33);
        memcpy(pSigBuf, p + 1, len - 1);
        *rawSignatureLen = len - 1;
        pSigBuf += len - 1; // Target ptr
    }
    else {
        ENSURE_OR_GO_EXIT(len <= (NX_RAW_SIGNATURE_LENGTH / 2));
        memcpy(pSigBuf + ((NX_RAW_SIGNATURE_LENGTH / 2) - len), p, len);
        *rawSignatureLen = (NX_RAW_SIGNATURE_LENGTH / 2);
        pSigBuf += (NX_RAW_SIGNATURE_LENGTH / 2); // Target ptr
    }

    p += len;
    // INTEGER
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_INTEGER)) != 0) {
        LOG_E("Signature s error");
        goto exit;
    }

    if (len == 0x21) {
        // p -> 00 [s]
        ENSURE_OR_GO_EXIT(len == 33);
        memcpy(pSigBuf, p + 1, len - 1);
        *rawSignatureLen += len - 1;
    }
    else {
        ENSURE_OR_GO_EXIT(len <= (NX_RAW_SIGNATURE_LENGTH / 2));
        memcpy(pSigBuf + ((NX_RAW_SIGNATURE_LENGTH / 2) - len), p, len);
        *rawSignatureLen += (NX_RAW_SIGNATURE_LENGTH / 2);
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t sss_nx_asymmetric_verify_digest(
    sss_nx_asymmetric_t *context, uint8_t *digest, size_t digestLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t retval                            = kStatus_SSS_Fail;
    smStatus_t status                              = SM_NOT_OK;
    uint16_t result                                = Nx_ECVerifyResult_Fail;
    SE_ECSignatureAlgo_t ecSignAlgo                = kSE_ECSignatureAlgo_NA;
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {0};
    size_t raw_signatureLen                        = sizeof(raw_signature);
    size_t offset                                  = 0;
    sss_status_t asn_retval                        = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(context != NULL);
    ENSURE_OR_GO_EXIT(signature != NULL);
    ENSURE_OR_GO_EXIT(digest != NULL);

    if (kStatus_SSS_Success != nx_check_input_len(digestLen, context->algorithm)) {
        LOG_E("Algorithm and digest length do not match");
        goto exit;
    }

    ecSignAlgo = nx_get_ec_sign_hash_mode(context->algorithm);
    if (kSE_ECSignatureAlgo_NA == ecSignAlgo) {
        LOG_E("Invalid algorithm");
        goto exit;
    }

    asn_retval = sss_util_decode_asn1_signature(raw_signature, &raw_signatureLen, signature, signatureLen);
    if (asn_retval != kStatus_SSS_Success) {
        LOG_E("Signature decoding failed");
        goto exit;
    }

    if (context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        offset = NX_BRAINPOOL_256_HEADER_LEN;
    }
    else if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
        offset = NX_NIST_256_HEADER_LEN;
    }
    else {
        LOG_E("Invalid cipher type");
        goto exit;
    }

    ENSURE_OR_GO_EXIT((context->keyObject->pubKeyLen > offset));
    status = nx_CryptoRequest_ECCVerify_Digest_Oneshot(&context->session->s_ctx,
        ecSignAlgo,
        context->keyObject->curve_id,
        (context->keyObject->pubKey + offset),
        (context->keyObject->pubKeyLen - offset),
        raw_signature,
        raw_signatureLen,
        kSE_CryptoDataSrc_CommandBuf,
        digest,
        digestLen,
        &result);
    ENSURE_OR_GO_EXIT(status == SM_OK);
    ENSURE_OR_GO_EXIT(result == Nx_ECVerifyResult_OK);

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_asymmetric_sign_one_go(
    sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen)
{
    sss_status_t retval                            = kStatus_SSS_Fail;
    smStatus_t status                              = SM_NOT_OK;
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {0};
    size_t raw_signatureLen                        = sizeof(raw_signature);
    sss_status_t asn_retval                        = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != signature);
    ENSURE_OR_GO_EXIT(NULL != signatureLen);
    ENSURE_OR_GO_EXIT(NULL != srcData);
    ENSURE_OR_GO_EXIT(context->keyObject->keyId <= UINT8_MAX);

    if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        SE_ECSignatureAlgo_t ecSignAlgo = nx_get_ec_sign_hash_mode(context->algorithm);
        if (ecSignAlgo == kSE_ECSignatureAlgo_NA) {
            LOG_E("Invalid algorithm 0x%x", ecSignAlgo);
            goto exit;
        }

        status = nx_CryptoRequest_ECCSign_Oneshot(&context->session->s_ctx,
            ecSignAlgo,
            context->keyObject->keyId,
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            srcLen,
            raw_signature,
            &raw_signatureLen);
        if (status != SM_OK) {
            LOG_E("ECC Sign oneshot failed");
            goto exit;
        }

        asn_retval = sss_util_encode_asn1_signature(signature, signatureLen, raw_signature, raw_signatureLen);
        if (asn_retval != kStatus_SSS_Success) {
            LOG_E("sss_util_asn1_ecdsa_get_signature failed");
            goto exit;
        }
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_asymmetric_sign_init(sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    smStatus_t status   = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != srcData);
    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(context->keyObject->keyId <= UINT8_MAX);

    if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        SE_ECSignatureAlgo_t ecSignAlgo = nx_get_ec_sign_hash_mode(context->algorithm);
        if (ecSignAlgo == kSE_ECSignatureAlgo_NA) {
            LOG_E("Invalid algorithm 0x%x", ecSignAlgo);
            goto exit;
        }

        status = nx_CryptoRequest_ECCSign_Init(&context->session->s_ctx,
            ecSignAlgo,
            context->keyObject->keyId,
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            srcLen);
        if (status != SM_OK) {
            LOG_E("ECC Sign init failed");
            goto exit;
        }
    }
    else {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_asymmetric_sign_update(sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    smStatus_t status   = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != srcData);

    if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        status =
            nx_CryptoRequest_ECCSign_Update(&context->session->s_ctx, kSE_CryptoDataSrc_CommandBuf, srcData, srcLen);
        if (status != SM_OK) {
            LOG_E("ECC Sign update failed");
            goto exit;
        }
    }
    else {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_asymmetric_sign_finish(
    sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t *signatureLen)
{
    sss_status_t retval                            = kStatus_SSS_Fail;
    smStatus_t status                              = SM_NOT_OK;
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {0};
    size_t raw_signatureLen                        = sizeof(raw_signature);
    sss_status_t asn_retval                        = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != srcData);
    ENSURE_OR_GO_EXIT(NULL != signature);
    ENSURE_OR_GO_EXIT(NULL != signatureLen);

    if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P ||
        context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        status = nx_CryptoRequest_ECCSign_Final(
            &context->session->s_ctx, kSE_CryptoDataSrc_CommandBuf, srcData, srcLen, raw_signature, &raw_signatureLen);
        if (status != SM_OK) {
            LOG_E("ECC Sign finish failed");
            goto exit;
        }

        asn_retval = sss_util_encode_asn1_signature(signature, signatureLen, raw_signature, raw_signatureLen);
        if (asn_retval != kStatus_SSS_Success) {
            LOG_E("sss_util_asn1_ecdsa_get_signature failed");
            goto exit;
        }
    }
    else {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_asymmetric_verify_one_go(
    sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t retval                            = kStatus_SSS_Fail;
    smStatus_t status                              = SM_NOT_OK;
    uint16_t result                                = Nx_ECVerifyResult_Fail;
    SE_ECSignatureAlgo_t ecSignAlgo                = kSE_ECSignatureAlgo_NA;
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {0};
    size_t raw_signatureLen                        = sizeof(raw_signature);
    size_t offset                                  = 0;
    sss_status_t asn_retval                        = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != signature);

    ecSignAlgo = nx_get_ec_sign_hash_mode(context->algorithm);
    if (kSE_ECSignatureAlgo_NA == ecSignAlgo) {
        LOG_E("Invalid algorithm");
        goto exit;
    }

    asn_retval = sss_util_decode_asn1_signature(raw_signature, &raw_signatureLen, signature, signatureLen);
    if (asn_retval != kStatus_SSS_Success) {
        LOG_E("Signature decoding failed");
        goto exit;
    }

    if (context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        offset = NX_BRAINPOOL_256_HEADER_LEN;
    }
    else if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
        offset = NX_NIST_256_HEADER_LEN;
    }
    else {
        LOG_E("Invalid cipher type");
        goto exit;
    }

    ENSURE_OR_GO_EXIT((context->keyObject->pubKeyLen > offset));
    status = nx_CryptoRequest_ECCVerify_Oneshot(&context->session->s_ctx,
        ecSignAlgo,
        context->keyObject->curve_id,
        (context->keyObject->pubKey + offset),
        (context->keyObject->pubKeyLen - offset),
        raw_signature,
        raw_signatureLen,
        kSE_CryptoDataSrc_CommandBuf,
        srcData,
        srcLen,
        &result);
    if (status == SM_OK) {
        if (Nx_ECVerifyResult_OK == result) {
            retval = kStatus_SSS_Success;
        }
    }

exit:
    return retval;
}

sss_status_t sss_nx_asymmetric_verify_init(sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval             = kStatus_SSS_Fail;
    smStatus_t status               = SM_NOT_OK;
    uint16_t result                 = Nx_ECVerifyResult_Fail;
    SE_ECSignatureAlgo_t ecSignAlgo = kSE_ECSignatureAlgo_NA;
    size_t offset                   = 0;

    ENSURE_OR_GO_EXIT(srcData != NULL);
    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);

    ecSignAlgo = nx_get_ec_sign_hash_mode(context->algorithm);
    if (kSE_ECSignatureAlgo_NA == ecSignAlgo) {
        LOG_E("Invalid algorithm");
        goto exit;
    }

    if (context->keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        offset = NX_BRAINPOOL_256_HEADER_LEN;
    }
    else if (context->keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
        offset = NX_NIST_256_HEADER_LEN;
    }
    else {
        LOG_E("Invalid cipher type");
        goto exit;
    }

    ENSURE_OR_GO_EXIT((context->keyObject->pubKeyLen > offset));
    status = nx_CryptoRequest_ECCVerify_Init(&context->session->s_ctx,
        ecSignAlgo,
        context->keyObject->curve_id,
        (context->keyObject->pubKey + offset),
        (context->keyObject->pubKeyLen - offset),
        kSE_CryptoDataSrc_CommandBuf,
        srcData,
        srcLen,
        &result);
    if (status == SM_OK) {
        if (Nx_ECVerifyResult_Init == result) {
            retval = kStatus_SSS_Success;
        }
    }

exit:
    return retval;
}

sss_status_t sss_nx_asymmetric_verify_update(sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    smStatus_t status   = SM_NOT_OK;
    uint16_t result     = Nx_ECVerifyResult_Fail;

    ENSURE_OR_GO_EXIT(srcData != NULL);
    ENSURE_OR_GO_EXIT(context != NULL);
    ENSURE_OR_GO_EXIT(context->session != NULL);

    status = nx_CryptoRequest_ECCVerify_Update(
        &context->session->s_ctx, kSE_CryptoDataSrc_CommandBuf, srcData, srcLen, &result);
    if (status == SM_OK) {
        if (Nx_ECVerifyResult_Init == result) {
            retval = kStatus_SSS_Success;
        }
    }

exit:
    return retval;
}

sss_status_t sss_nx_asymmetric_verify_finish(
    sss_nx_asymmetric_t *context, uint8_t *srcData, size_t srcLen, uint8_t *signature, size_t signatureLen)
{
    sss_status_t retval                            = kStatus_SSS_Fail;
    smStatus_t status                              = SM_NOT_OK;
    uint16_t result                                = Nx_ECVerifyResult_Fail;
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {0};
    size_t raw_signatureLen                        = sizeof(raw_signature);

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(NULL != signature);
    ENSURE_OR_GO_EXIT(NULL != srcData);

    sss_status_t asn_retval = kStatus_SSS_Fail;
    asn_retval              = sss_util_decode_asn1_signature(raw_signature, &raw_signatureLen, signature, signatureLen);
    if (asn_retval != kStatus_SSS_Success) {
        LOG_E("Failed");
        goto exit;
    }

    status = nx_CryptoRequest_ECCVerify_Final(&context->session->s_ctx,
        raw_signature,
        raw_signatureLen,
        kSE_CryptoDataSrc_CommandBuf,
        srcData,
        srcLen,
        &result);
    if (status == SM_OK) {
        if (Nx_ECVerifyResult_OK == result) {
            retval = kStatus_SSS_Success;
        }
    }

exit:
    return retval;
}

void sss_nx_asymmetric_context_free(sss_nx_asymmetric_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        memset(context, 0, sizeof(*context));
    }
}

static Nx_AES_Primitive_t nx_get_cipher_primitive(sss_algorithm_t algorithm, sss_mode_t mode)
{
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;
    switch (algorithm) {
    case kAlgorithm_SSS_AES_ECB:
        if (mode == kMode_SSS_Encrypt) {
            primitive = Nx_AES_Primitive_ECB_Encrypt;
        }
        else {
            primitive = Nx_AES_Primitive_ECB_Decrypt;
        }
        break;
    case kAlgorithm_SSS_AES_CBC:
        if (mode == kMode_SSS_Encrypt) {
            primitive = Nx_AES_Primitive_CBC_Encrypt;
        }
        else {
            primitive = Nx_AES_Primitive_CBC_Decrypt;
        }
        break;
    default:
        primitive = Nx_AES_Primitive_NA;
    }
    return primitive;
}

sss_status_t sss_nx_symmetric_context_init(sss_nx_symmetric_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context)
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;

    retval = kStatus_SSS_Success;

exit:
    return retval;
}

sss_status_t sss_nx_cipher_one_go(
    sss_nx_symmetric_t *context, uint8_t *iv, size_t ivLen, const uint8_t *srcData, uint8_t *destData, size_t dataLen)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(context->keyObject->keyId <= UINT8_MAX);
    ENSURE_OR_GO_EXIT(NULL != srcData);
    ENSURE_OR_GO_EXIT(NULL != destData);

    primitive = nx_get_cipher_primitive(context->algorithm, context->mode);
    ENSURE_OR_GO_EXIT(primitive != Nx_AES_Primitive_NA);

    status = nx_CryptoRequest_AES_CBC_ECB_Oneshot(&context->session->s_ctx,
        primitive,
        context->keyObject->keyId,
        context->keyObject->keyLen,
        kSE_CryptoDataSrc_CommandBuf,
        iv,
        ivLen,
        kSE_CryptoDataSrc_CommandBuf,
        srcData,
        dataLen,
        kSE_CryptoDataSrc_CommandBuf,
        destData);
    if (status != SM_OK) {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_cipher_init(sss_nx_symmetric_t *context, uint8_t *iv, size_t ivLen)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;
    uint8_t outputData[16]       = {0};
    size_t outputDataLen         = sizeof(outputData);

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    primitive = nx_get_cipher_primitive(context->algorithm, context->mode);
    ENSURE_OR_GO_EXIT(primitive != Nx_AES_Primitive_NA);
    ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);

    status = nx_CryptoRequest_AES_CBC_ECB_Init(&context->session->s_ctx,
        primitive,
        (uint8_t)context->keyObject->keyId,
        context->keyObject->keyLen,
        kSE_CryptoDataSrc_CommandBuf,
        iv,
        ivLen,
        kSE_CryptoDataSrc_CommandBuf,
        NULL,
        0,
        outputData,
        &outputDataLen);
    if (status != SM_OK) {
        goto exit;
    }
    if (outputDataLen != 0) {
        LOG_E("sss_nx_cipher_init get abnormal output data!!!");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_cipher_update(
    sss_nx_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(NULL != destData);
    ENSURE_OR_GO_EXIT(NULL != destLen);

    primitive = nx_get_cipher_primitive(context->algorithm, context->mode);
    ENSURE_OR_GO_EXIT(primitive != Nx_AES_Primitive_NA);

    status = nx_CryptoRequest_AES_CBC_ECB_Update(
        &context->session->s_ctx, kSE_CryptoDataSrc_CommandBuf, srcData, srcLen, destData, destLen);
    if (status != SM_OK) {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_cipher_finish(
    sss_nx_symmetric_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != destData);
    ENSURE_OR_GO_EXIT(NULL != destLen);

    primitive = nx_get_cipher_primitive(context->algorithm, context->mode);
    ENSURE_OR_GO_EXIT(primitive != Nx_AES_Primitive_NA);

    status = nx_CryptoRequest_AES_CBC_ECB_Final(
        &context->session->s_ctx, kSE_CryptoDataSrc_CommandBuf, srcData, srcLen, destData, destLen);
    if (status != SM_OK) {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_nx_symmetric_context_free(sss_nx_symmetric_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        memset(context, 0, sizeof(*context));
    }
}

static Nx_AES_Primitive_t nx_get_aead_primitive(sss_algorithm_t algorithm, sss_mode_t mode)
{
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;
    switch (algorithm) {
    case kAlgorithm_SSS_AES_GCM:
        if (mode == kMode_SSS_Encrypt) {
            primitive = Nx_AES_Primitive_GCM_Encrypt_Sign;
        }
        else if (mode == kMode_SSS_Decrypt) {
            primitive = Nx_AES_Primitive_GCM_Decrypt_Verify;
        }
        else {
            primitive = Nx_AES_Primitive_NA;
        }
        break;

    case kAlgorithm_SSS_AES_GCM_INT_IV:
        if (mode == kMode_SSS_Encrypt) {
            primitive = Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce;
        }
        else {
            primitive = Nx_AES_Primitive_NA;
        }
        break;

    case kAlgorithm_SSS_AES_CCM:
        if (mode == kMode_SSS_Encrypt) {
            primitive = Nx_AES_Primitive_CCM_Encrypt_Sign;
        }
        else if (mode == kMode_SSS_Decrypt) {
            primitive = Nx_AES_Primitive_CCM_Decrypt_Verify;
        }
        else {
            primitive = Nx_AES_Primitive_NA;
        }
        break;

    case kAlgorithm_SSS_AES_CCM_INT_IV:
        if (mode == kMode_SSS_Encrypt) {
            primitive = Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce;
        }
        else {
            primitive = Nx_AES_Primitive_NA;
        }
        break;

    default:
        primitive = Nx_AES_Primitive_NA;
    }
    return primitive;
}

sss_status_t sss_nx_aead_context_init(sss_nx_aead_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context)
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;

    retval = kStatus_SSS_Success;

exit:
    return retval;
}

sss_status_t sss_nx_aead_one_go(sss_nx_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(context != NULL);

    /* Check mode do the operation requested */
    if (context->mode == kMode_SSS_Encrypt) {
        retval = nx_aead_one_go_encrypt(context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        retval = nx_aead_one_go_decrypt(context, srcData, destData, size, nonce, nonceLen, aad, aadLen, tag, tagLen);
    }

exit:
    return retval;
}

static sss_status_t nx_aead_one_go_encrypt(sss_nx_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    primitive = nx_get_aead_primitive(context->algorithm, context->mode);
    ENSURE_OR_GO_EXIT(primitive != Nx_AES_Primitive_NA);

    if ((primitive == Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce ||
            primitive == Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce)) {
        if (nonceLen > 0) {
            ENSURE_OR_GO_EXIT(nonce != NULL);
        }
        ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);
        status = nx_CryptoRequest_AES_AEAD_Oneshot(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Encrypt_Sign,
            primitive,
            (uint8_t)context->keyObject->keyId,
            context->keyObject->keyLen,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            nonceLen,
            &nonce[0],
            *tagLen,
            NULL,
            &tag[0],
            kSE_CryptoDataSrc_CommandBuf,
            aad,
            aadLen,
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            size,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            &destData[0]);
        if (status != SM_OK) {
            goto exit;
        }
    }
    else if (primitive == Nx_AES_Primitive_CCM_Encrypt_Sign || primitive == Nx_AES_Primitive_GCM_Encrypt_Sign) {
        ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);
        status = nx_CryptoRequest_AES_AEAD_Oneshot(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Encrypt_Sign,
            primitive,
            (uint8_t)context->keyObject->keyId,
            context->keyObject->keyLen,
            kSE_CryptoDataSrc_CommandBuf,
            nonce,
            nonceLen,
            NULL,
            *tagLen,
            NULL,
            &tag[0],
            kSE_CryptoDataSrc_CommandBuf,
            aad,
            aadLen,
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            size,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            &destData[0]);
        if (status != SM_OK) {
            goto exit;
        }
    }
    else {
        LOG_E("Unknown primitive type");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

static sss_status_t nx_aead_one_go_decrypt(sss_nx_aead_t *context,
    const uint8_t *srcData,
    uint8_t *destData,
    size_t size,
    uint8_t *nonce,
    size_t nonceLen,
    const uint8_t *aad,
    size_t aadLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;
    uint16_t verifyResult        = Nx_ECVerifyResult_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    primitive = nx_get_aead_primitive(context->algorithm, context->mode);
    ENSURE_OR_GO_EXIT(primitive != Nx_AES_Primitive_NA);

    if ((primitive == Nx_AES_Primitive_CCM_Decrypt_Verify || primitive == Nx_AES_Primitive_GCM_Decrypt_Verify)) {
        ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);
        status = nx_CryptoRequest_AES_AEAD_Oneshot(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Decrypt_Verify,
            primitive,
            (uint8_t)context->keyObject->keyId,
            context->keyObject->keyLen,
            kSE_CryptoDataSrc_CommandBuf,
            nonce,
            nonceLen,
            NULL,
            *tagLen,
            tag,
            NULL,
            kSE_CryptoDataSrc_CommandBuf,
            aad,
            aadLen,
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            size,
            kSE_CryptoDataSrc_CommandBuf,
            &verifyResult,
            &destData[0]);
        if (status != SM_OK) {
            goto exit;
        }

        if (verifyResult != Nx_AES_AEAD_Verify_OK) {
            goto exit;
        }
    }
    else {
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_aead_init(
    sss_nx_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(context != NULL);

    /* Check mode do the operation requested */
    if (context->mode == kMode_SSS_Encrypt) {
        retval = nx_aead_encrypt_init(context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        retval = nx_aead_decrypt_init(context, nonce, nonceLen, tagLen, aadLen, payloadLen);
    }

exit:
    return retval;
}

// aadLen is totalaadLen and payloadLen is totalinputLen
static sss_status_t nx_aead_encrypt_init(
    sss_nx_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    primitive = nx_get_aead_primitive(context->algorithm, context->mode);
    ENSURE_OR_GO_EXIT(primitive != Nx_AES_Primitive_NA);

    if ((primitive == Nx_AES_Primitive_CCM_Encrypt_Sign_internal_nonce ||
            primitive == Nx_AES_Primitive_GCM_Encrypt_Sign_internal_nonce)) {
        if (nonceLen > 0) {
            ENSURE_OR_GO_EXIT(nonce != NULL);
        }
        ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);
        status = nx_CryptoRequest_AES_AEAD_Init(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Encrypt_Sign,
            primitive,
            (uint8_t)context->keyObject->keyId,
            context->keyObject->keyLen,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            nonceLen,
            &nonce[0],
            aadLen,
            payloadLen,
            tagLen,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            NULL);
        if (status != SM_OK) {
            goto exit;
        }
    }
    else if (primitive == Nx_AES_Primitive_CCM_Encrypt_Sign || primitive == Nx_AES_Primitive_GCM_Encrypt_Sign) {
        if (nonceLen > 0) {
            ENSURE_OR_GO_EXIT(nonce != NULL);
        }
        ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);
        status = nx_CryptoRequest_AES_AEAD_Init(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Encrypt_Sign,
            primitive,
            (uint8_t)context->keyObject->keyId,
            context->keyObject->keyLen,
            kSE_CryptoDataSrc_CommandBuf,
            nonce,
            nonceLen,
            NULL,
            aadLen,
            payloadLen,
            tagLen,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            NULL);
        if (status != SM_OK) {
            goto exit;
        }
    }
    else {
        LOG_E("Unknown primitive type");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

static sss_status_t nx_aead_decrypt_init(
    sss_nx_aead_t *context, uint8_t *nonce, size_t nonceLen, size_t tagLen, size_t aadLen, size_t payloadLen)
{
    sss_status_t retval          = kStatus_SSS_Fail;
    smStatus_t status            = SM_NOT_OK;
    Nx_AES_Primitive_t primitive = Nx_AES_Primitive_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    primitive = nx_get_aead_primitive(context->algorithm, context->mode);
    ENSURE_OR_GO_EXIT(primitive != Nx_AES_Primitive_NA);
    ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);

    status = nx_CryptoRequest_AES_AEAD_Init(&context->session->s_ctx,
        Nx_CryptoAPI_Operation_AES_Decrypt_Verify,
        primitive,
        (uint8_t)context->keyObject->keyId,
        context->keyObject->keyLen,
        kSE_CryptoDataSrc_CommandBuf,
        nonce,
        nonceLen,
        NULL,
        aadLen,
        payloadLen,
        tagLen,
        kSE_CryptoDataSrc_CommandBuf,
        NULL,
        0,
        kSE_CryptoDataSrc_CommandBuf,
        NULL,
        0,
        kSE_CryptoDataSrc_CommandBuf,
        NULL,
        NULL);
    ENSURE_OR_GO_EXIT(status == SM_OK);

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_aead_update_aad(sss_nx_aead_t *context, const uint8_t *aadData, size_t aadDataLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    smStatus_t status   = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    if (context->mode == kMode_SSS_Encrypt) {
        status = nx_CryptoRequest_AES_AEAD_Update(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Encrypt_Sign,
            kSE_CryptoDataSrc_CommandBuf,
            aadData,
            aadDataLen,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            NULL);
        ENSURE_OR_GO_EXIT(status == SM_OK);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        status = nx_CryptoRequest_AES_AEAD_Update(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Decrypt_Verify,
            kSE_CryptoDataSrc_CommandBuf,
            aadData,
            aadDataLen,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            NULL);
        ENSURE_OR_GO_EXIT(status == SM_OK);
    }
    else {
        LOG_E("Unknown mode");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_aead_update(
    sss_nx_aead_t *context, const uint8_t *srcData, size_t srcLen, uint8_t *destData, size_t *destLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    smStatus_t status   = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    if (context->mode == kMode_SSS_Encrypt) {
        status = nx_CryptoRequest_AES_AEAD_Update(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Encrypt_Sign,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            srcLen,
            kSE_CryptoDataSrc_CommandBuf,
            &destData[0],
            destLen);
        ENSURE_OR_GO_EXIT(status == SM_OK);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        status = nx_CryptoRequest_AES_AEAD_Update(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Decrypt_Verify,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            srcLen,
            kSE_CryptoDataSrc_CommandBuf,
            &destData[0],
            destLen);
        ENSURE_OR_GO_EXIT(status == SM_OK);
    }
    else {
        LOG_E("Unknown mode");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_aead_finish(sss_nx_aead_t *context,
    const uint8_t *srcData,
    size_t srcLen,
    uint8_t *destData,
    size_t *destLen,
    uint8_t *tag,
    size_t *tagLen)
{
    sss_status_t retval   = kStatus_SSS_Fail;
    smStatus_t status     = SM_NOT_OK;
    uint16_t verifyResult = Nx_ECVerifyResult_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    if (context->mode == kMode_SSS_Encrypt) {
        ENSURE_OR_GO_EXIT(NULL != tagLen);
        status = nx_CryptoRequest_AES_AEAD_Final(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Encrypt_Sign,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            *tagLen,
            NULL,
            &tag[0],
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            srcLen,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            &destData[0],
            destLen);
        ENSURE_OR_GO_EXIT(status == SM_OK);
    }
    else if (context->mode == kMode_SSS_Decrypt) {
        ENSURE_OR_GO_EXIT(NULL != tagLen);
        status = nx_CryptoRequest_AES_AEAD_Final(&context->session->s_ctx,
            Nx_CryptoAPI_Operation_AES_Decrypt_Verify,
            kSE_CryptoDataSrc_CommandBuf,
            NULL,
            0,
            *tagLen,
            tag,
            NULL,
            kSE_CryptoDataSrc_CommandBuf,
            srcData,
            srcLen,
            kSE_CryptoDataSrc_CommandBuf,
            &verifyResult,
            &destData[0],
            destLen);
        ENSURE_OR_GO_EXIT(status == SM_OK);
        if (verifyResult != Nx_AES_AEAD_Verify_OK) {
            goto exit;
        }
    }
    else {
        LOG_E("Unknown mode");
        goto exit;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_nx_aead_context_free(sss_nx_aead_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        memset(context, 0, sizeof(*context));
    }
}

sss_status_t sss_nx_digest_context_init(
    sss_nx_digest_t *context, sss_nx_session_t *session, sss_algorithm_t algorithm, sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context)
    context->session   = session;
    context->algorithm = algorithm;
    context->mode      = mode;
    retval             = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_digest_one_go(
    sss_nx_digest_t *context, const uint8_t *message, size_t messageLen, uint8_t *digest, size_t *digestLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    smStatus_t status   = SM_NOT_OK;
    uint8_t sha_type    = kSE_DigestMode_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    sha_type = nx_get_sha_algo(context->algorithm);
    ENSURE_OR_GO_EXIT(sha_type != kSE_DigestMode_NA);

    status = nx_CryptoRequest_SHA_Oneshot(&context->session->s_ctx,
        sha_type,
        kSE_CryptoDataSrc_CommandBuf,
        message,
        messageLen,
        kSE_CryptoDataSrc_CommandBuf,
        digest,
        digestLen);
    if (status != SM_OK) {
        *digestLen = 0;
        goto exit;
    }
    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_digest_init(sss_nx_digest_t *context)
{
    sss_status_t retval = kStatus_SSS_Fail;
    uint8_t sha_type    = kSE_DigestMode_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    context->init_done = 0;

    sha_type = nx_get_sha_algo(context->algorithm);
    ENSURE_OR_GO_EXIT(sha_type != kSE_DigestMode_NA);

    // Do nothing. Call init in update function.

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_digest_update(sss_nx_digest_t *context, const uint8_t *message, size_t messageLen)
{
    sss_status_t retval      = kStatus_SSS_Fail;
    smStatus_t status        = SM_NOT_OK;
    uint8_t sha_type         = kSE_DigestMode_NA;
    smStatus_t (*func_ptr)(pSeSession_t session_ctx,
        uint8_t algorithm,
        uint8_t inputDataSrc,
        const uint8_t *inputData,
        size_t inputDataLen) = NULL;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != context->session)

    sha_type = nx_get_sha_algo(context->algorithm);
    ENSURE_OR_GO_EXIT(sha_type != kSE_DigestMode_NA);

    if (context->init_done == 0) {
        func_ptr = &nx_CryptoRequest_SHA_Init;
    }
    else {
        func_ptr = &nx_CryptoRequest_SHA_Update;
    }

    if (message != NULL) {
        status = func_ptr(&context->session->s_ctx, sha_type, 0, message, messageLen);
        ENSURE_OR_GO_EXIT(SM_OK == status);
    }
    else {
        goto exit;
    }

    context->init_done = 1;
    retval             = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_digest_finish(sss_nx_digest_t *context, uint8_t *digest, size_t *digestLen)
{
    sss_status_t retval = kStatus_SSS_Fail;
    smStatus_t status   = SM_NOT_OK;
    uint8_t sha_type    = kSE_DigestMode_NA;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(NULL != digest);

    sha_type = nx_get_sha_algo(context->algorithm);
    ENSURE_OR_GO_EXIT(sha_type != kSE_DigestMode_NA);

    status = nx_CryptoRequest_SHA_Final(
        &context->session->s_ctx, sha_type, 0, NULL, 0, kSE_CryptoDataSrc_CommandBuf, digest, digestLen);
    ENSURE_OR_GO_EXIT(SM_OK == status);

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_nx_digest_context_free(sss_nx_digest_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        memset(context, 0, sizeof(*context));
    }
}

sss_status_t sss_nx_rng_context_init(sss_nx_rng_context_t *context, sss_nx_session_t *session)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context)
    context->session = session;
    retval           = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_rng_get_random(sss_nx_rng_context_t *context, uint8_t *randomData, size_t randomDataLen)
{
    sss_status_t retval      = kStatus_SSS_Fail;
    smStatus_t status        = SM_NOT_OK;
    size_t randomDataPending = randomDataLen;
    size_t chunkReqd         = 0;
    size_t offset            = 0;

    ENSURE_OR_GO_EXIT(NULL != context)
    ENSURE_OR_GO_EXIT(NULL != context->session)

    while (randomDataPending > 0) {
        chunkReqd = (randomDataPending > NX_MAX_RND_DATA_LEN) ? NX_MAX_RND_DATA_LEN : randomDataPending;

        status = nx_CryptoRequest_RNG(&context->session->s_ctx,
            (uint8_t)chunkReqd,
            kSE_CryptoDataSrc_CommandBuf,
            (randomData + offset),
            &chunkReqd);
        ENSURE_OR_GO_EXIT(status == SM_OK);

        offset += chunkReqd;
        randomDataPending -= chunkReqd;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_rng_context_free(sss_nx_rng_context_t *context)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context)
    memset(context, 0, sizeof(*context));

    retval = kStatus_SSS_Success;

exit:
    return retval;
}

sss_status_t sss_nx_derive_key_context_init(sss_nx_derive_key_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context)
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;

    retval = kStatus_SSS_Success;

exit:
    return retval;
}

void sss_nx_derive_key_context_free(sss_nx_derive_key_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        memset(context, 0, sizeof(*context));
    }
}

sss_status_t sss_nx_derive_key_dh_one_go(
    sss_nx_derive_key_t *context, sss_nx_object_t *otherPartyKeyObject, sss_nx_object_t *derivedKeyObject)
{
    sss_status_t retval                 = kStatus_SSS_Fail;
    smStatus_t status                   = SM_NOT_OK;
    uint8_t otherPartyPubKey[256]       = {0};
    size_t otherPartyPubKeyLen          = sizeof(otherPartyPubKey);
    size_t otherPartyPubKeyBitLen       = 0;
    uint8_t sharedSecret[32]            = {0};
    size_t sharedSecretLen              = sizeof(sharedSecret);
    sss_nx_object_t *keyObject          = NULL;
    sss_object_t *sss_other_keyObject   = NULL;
    sss_object_t *sss_derived_keyObject = NULL;
    sss_cipher_type_t cipher_type       = kSSS_CipherType_NONE;
    size_t keyOffset                    = 0;
    uint8_t *pubKey                     = NULL;
    size_t pubKeyBufLen                 = 0;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(NULL != otherPartyKeyObject);
    ENSURE_OR_GO_EXIT(NULL != derivedKeyObject);

    cipher_type           = (sss_cipher_type_t)otherPartyKeyObject->cipherType;
    keyObject             = (sss_nx_object_t *)(context->keyObject);
    sss_other_keyObject   = (sss_object_t *)otherPartyKeyObject;
    sss_derived_keyObject = (sss_object_t *)derivedKeyObject;

    if (cipher_type == kSSS_CipherType_EC_BRAINPOOL) {
        keyOffset = NX_BRAINPOOL_256_HEADER_LEN;
    }
    else if (cipher_type == kSSS_CipherType_EC_NIST_P) {
        keyOffset = NX_NIST_256_HEADER_LEN;
    }
    else {
        // Invalid cipher type
        goto exit;
    }

    retval = sss_key_store_get_key((sss_key_store_t *)sss_other_keyObject->keyStore,
        sss_other_keyObject,
        otherPartyPubKey,
        &otherPartyPubKeyLen,
        &otherPartyPubKeyBitLen);
    ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);

    retval = kStatus_SSS_Fail; //re-initialization

    if (keyOffset >= otherPartyPubKeyLen) {
        LOG_E("Host Public Key is invalid !!!");
        goto exit;
    }

    if ((keyObject->keyId == NX_KEY_ID_EPHEM_NISTP256) || (keyObject->keyId == NX_KEY_ID_EPHEM_BP256)) {
        // Add header to key
        if (keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
            ENSURE_OR_GO_EXIT(sizeof(keyObject->pubKey) > der_ecc_nistp256_header_len);
            memcpy(keyObject->pubKey, gecc_der_header_nist256, der_ecc_nistp256_header_len);
            keyObject->pubKeyLen = der_ecc_nistp256_header_len;
        }
        else if (keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
            ENSURE_OR_GO_EXIT(sizeof(keyObject->pubKey) > der_ecc_bp256_header_len);
            memcpy(keyObject->pubKey, gecc_der_header_bp256, der_ecc_bp256_header_len);
            keyObject->pubKeyLen = der_ecc_bp256_header_len;
        }
        else {
            LOG_E("Invalid cipher type!");
            goto exit;
        }

        pubKeyBufLen = sizeof(keyObject->pubKey) - (keyObject->pubKeyLen);
        pubKey       = keyObject->pubKey + (keyObject->pubKeyLen);
    }
    else {
        pubKey       = NULL;
        pubKeyBufLen = 0;
    }

    if (derivedKeyObject->cipherType == kSSS_CipherType_BufferSlots) {
        ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);
        ENSURE_OR_GO_EXIT((derivedKeyObject->keyId) <= UINT8_MAX);
        // Transient / static buffer
        status = nx_CryptoRequest_ECDH_Oneshot(&context->session->s_ctx,
            (uint8_t)context->keyObject->keyId,
            derivedKeyObject->keyId,
            otherPartyPubKey + keyOffset,
            otherPartyPubKeyLen - keyOffset,
            NULL,
            NULL,
            pubKey,
            &pubKeyBufLen);
        if (status != SM_OK) {
            LOG_E("error in nx_CryptoRequest_ECDH_Oneshot");
            goto exit;
        }
        // Output 32 byte shared secret.
        derivedKeyObject->keyLen = 32;
    }
    else {
        ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);
        // Command buffer
        status = nx_CryptoRequest_ECDH_Oneshot(&context->session->s_ctx,
            (uint8_t)context->keyObject->keyId,
            kSE_CryptoDataSrc_CommandBuf,
            otherPartyPubKey + keyOffset,
            otherPartyPubKeyLen - keyOffset,
            sharedSecret,
            &sharedSecretLen,
            pubKey,
            &pubKeyBufLen);
        if (status != SM_OK) {
            LOG_E("error in nx_CryptoRequest_ECDH_Oneshot");
            goto exit;
        }

        retval = sss_key_store_set_key((sss_key_store_t *)sss_derived_keyObject->keyStore,
            sss_derived_keyObject,
            sharedSecret,
            sharedSecretLen,
            sharedSecretLen * 8,
            NULL,
            0);
        ENSURE_OR_GO_EXIT(retval == kStatus_SSS_Success);
    }

    if ((keyObject->keyId == NX_KEY_ID_EPHEM_NISTP256) || (keyObject->keyId == NX_KEY_ID_EPHEM_BP256)) {
        // Ephemeral Public key length
        keyObject->pubKeyLen += pubKeyBufLen;
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_derive_key_dh_two_step_part1(sss_nx_derive_key_t *context)
{
    sss_status_t retval        = kStatus_SSS_Fail;
    smStatus_t status          = SM_NOT_OK;
    sss_nx_object_t *keyObject = NULL;
    uint8_t *pubKey            = NULL;
    size_t pubKeyBufLen        = 0;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);

    keyObject = (sss_nx_object_t *)(context->keyObject);
    ENSURE_OR_GO_EXIT((context->keyObject->keyId == NX_KEY_ID_EPHEM_NISTP256) ||
                      (context->keyObject->keyId == NX_KEY_ID_EPHEM_BP256));

    // Add header to key
    if (keyObject->cipherType == kSSS_CipherType_EC_NIST_P) {
        ENSURE_OR_GO_EXIT(sizeof(keyObject->pubKey) > der_ecc_nistp256_header_len);
        memcpy(keyObject->pubKey, gecc_der_header_nist256, der_ecc_nistp256_header_len);
        keyObject->pubKeyLen = der_ecc_nistp256_header_len;
    }
    else if (keyObject->cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        ENSURE_OR_GO_EXIT(sizeof(keyObject->pubKey) > der_ecc_bp256_header_len);
        memcpy(keyObject->pubKey, gecc_der_header_bp256, der_ecc_bp256_header_len);
        keyObject->pubKeyLen = der_ecc_bp256_header_len;
    }
    else {
        LOG_E("Invalid cipher type");
        goto exit;
    }

    ENSURE_OR_GO_EXIT(sizeof(keyObject->pubKey) > keyObject->pubKeyLen);
    pubKeyBufLen = sizeof(keyObject->pubKey) - (keyObject->pubKeyLen);
    pubKey       = keyObject->pubKey + (keyObject->pubKeyLen);

    status =
        nx_CryptoRequest_ECDH_TwoStepPart1(&context->session->s_ctx, context->keyObject->keyId, pubKey, &pubKeyBufLen);

    if (status != SM_OK) {
        LOG_W("error in nx_CryptoRequest_ECDH_TwoStepPart1");
        goto exit;
    }

    keyObject->pubKeyLen += pubKeyBufLen;

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_derive_key_dh_two_step_part2(
    sss_nx_derive_key_t *context, sss_nx_object_t *otherPartyKeyObject, sss_nx_object_t *derivedKeyObject)
{
    sss_status_t retval                 = kStatus_SSS_Fail;
    sss_status_t sss_status             = kStatus_SSS_Fail;
    smStatus_t status                   = SM_NOT_OK;
    sss_cipher_type_t cipher_type       = kSSS_CipherType_NONE;
    uint8_t otherPartyPubKey[256]       = {0};
    size_t otherPartyPubKeyLen          = sizeof(otherPartyPubKey);
    size_t otherPartyPubKeyBitLen       = 0;
    uint8_t sharedSecret[32]            = {0};
    size_t sharedSecretLen              = sizeof(sharedSecret);
    size_t keyOffset                    = 0;
    sss_object_t *sss_other_keyObject   = NULL;
    sss_object_t *sss_derived_keyObject = NULL;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != otherPartyKeyObject);
    ENSURE_OR_GO_EXIT(NULL != derivedKeyObject);
    ENSURE_OR_GO_EXIT((context->keyObject) != NULL);
    ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);

    cipher_type = (sss_cipher_type_t)otherPartyKeyObject->cipherType;
    if (cipher_type == kSSS_CipherType_EC_BRAINPOOL) {
        keyOffset = NX_BRAINPOOL_256_HEADER_LEN;
    }
    else if (cipher_type == kSSS_CipherType_EC_NIST_P) {
        keyOffset = NX_NIST_256_HEADER_LEN;
    }
    else {
        LOG_E("Invalid cipher type!");
        goto exit;
    }

    sss_other_keyObject   = (sss_object_t *)otherPartyKeyObject;
    sss_derived_keyObject = (sss_object_t *)derivedKeyObject;

    sss_status = sss_key_store_get_key((sss_key_store_t *)sss_other_keyObject->keyStore,
        sss_other_keyObject,
        otherPartyPubKey,
        &otherPartyPubKeyLen,
        &otherPartyPubKeyBitLen);
    ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);

    if (keyOffset >= otherPartyPubKeyLen) {
        LOG_E("Host Public Key parsing failed !!!");
        goto exit;
    }

    if (derivedKeyObject->cipherType == kSSS_CipherType_BufferSlots) {
        // Transient buffer
        ENSURE_OR_GO_EXIT((context->keyObject->keyId) <= UINT8_MAX);
        ENSURE_OR_GO_EXIT((derivedKeyObject->keyId) <= UINT8_MAX);
        status = nx_CryptoRequest_ECDH_TwoStepPart2(&context->session->s_ctx,
            context->keyObject->keyId,
            derivedKeyObject->keyId,
            otherPartyPubKey + keyOffset,
            otherPartyPubKeyLen - keyOffset,
            NULL,
            NULL);
        if (status != SM_OK) {
            LOG_E("error in nx_CryptoRequest_ECDH_TwoStepPart2");
            goto exit;
        }
    }
    else {
        // Command buffer
        status = nx_CryptoRequest_ECDH_TwoStepPart2(&context->session->s_ctx,
            context->keyObject->keyId,
            kSE_CryptoDataSrc_CommandBuf,
            otherPartyPubKey + keyOffset,
            otherPartyPubKeyLen - keyOffset,
            sharedSecret,
            &sharedSecretLen);
        if (status != SM_OK) {
            LOG_E("error in nx_CryptoRequest_ECDH_TwoStepPart2");
            goto exit;
        }

        sss_status = sss_key_store_set_key((sss_key_store_t *)sss_derived_keyObject->keyStore,
            sss_derived_keyObject,
            sharedSecret,
            sharedSecretLen,
            sharedSecretLen * 8,
            NULL,
            0);
        ENSURE_OR_GO_EXIT(sss_status == kStatus_SSS_Success);
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_derive_key_one_go(sss_nx_derive_key_t *context,
    sss_object_t *saltObject,
    const uint8_t *info,
    size_t infoLen,
    sss_object_t *derivedKeyObject,
    uint16_t deriveDataLen)
{
    sss_status_t retval     = kStatus_SSS_Fail;
    smStatus_t status       = SM_NOT_OK;
    uint8_t digestOperation = 0x01; /* 0x01 - SHA256, 0x02 - SHA384 */
    uint8_t hkdfOperation   = 0x00; /* 0x00 - extract and expand, 0x01 - expand only */

    uint8_t saltSrc         = 0;
    uint8_t outDest         = 0;
    uint8_t *saltData       = NULL;
    size_t saltDataLen      = 0;
    uint8_t hkdfOutput[256] = {0};
    size_t hkdfOutputLen    = sizeof(hkdfOutput);
    uint8_t *hkdfData       = NULL;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(NULL != info);

    switch (context->algorithm) {
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_HMAC_SHA256: {
        digestOperation = 0x01;
    } break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_HMAC_SHA384: {
        digestOperation = 0x02;
    } break;
    default: {
        LOG_E("Unknown algorithm");
        goto exit;
    }
    }

    switch (context->mode) {
    case kMode_SSS_HKDF_ExtractExpand: {
        hkdfOperation = Nx_HKDFOperation_ExtractAndExpand;
    } break;
    case kMode_SSS_HKDF_ExpandOnly: {
        hkdfOperation = Nx_HKDFOperation_Expand_Only;
    } break;
    default: {
        LOG_E("Unknown algorithm");
        goto exit;
    }
    }

    /* note :
        IKM in only AES keys are handled. For IKM in transient or static buffer, use nx_CryptoRequest_HKDF direclty
    */
    ENSURE_OR_GO_EXIT(context->keyObject->keyId <= UINT8_MAX);

    if (saltObject != NULL) {
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
        if (saltObject->keyStore->session->subsystem == kType_SSS_mbedTLS) {
            saltSrc     = kSE_CryptoDataSrc_CommandBuf;
            saltData    = ((sss_mbedtls_object_t *)saltObject)->contents;
            saltDataLen = ((sss_mbedtls_object_t *)saltObject)->contents_size;
            goto calc_hkdf;
        }
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
        if (saltObject->keyStore->session->subsystem == kType_SSS_OpenSSL) {
            saltSrc     = kSE_CryptoDataSrc_CommandBuf;
            saltData    = ((sss_openssl_object_t *)saltObject)->contents;
            saltDataLen = ((sss_openssl_object_t *)saltObject)->contents_size;
            goto calc_hkdf;
        }
#endif
        if ((saltObject->keyStore->session->subsystem == kType_SSS_SE_NX)) {
            if ((saltObject->keyId < UINT8_MAX) && (sss_nx_check_slot_num_valid(saltObject->keyId))) {
                saltSrc     = saltObject->keyId;
                saltData    = NULL;
                saltDataLen = ((sss_nx_object_t *)saltObject)->keyLen;
            }
            else {
                LOG_E("Salt key object is neither on host, nor points to slot in nx");
                goto exit;
            }
        }
        else {
            LOG_E("Invalid subsystem for Salt key object");
            goto exit;
        }
    }

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS || SSS_HAVE_HOSTCRYPTO_OPENSSL
calc_hkdf:
#endif

    if (derivedKeyObject->keyStore->session->subsystem == kType_SSS_mbedTLS ||
        derivedKeyObject->keyStore->session->subsystem == kType_SSS_OpenSSL) {
        outDest  = kSE_CryptoDataSrc_CommandBuf;
        hkdfData = hkdfOutput;
    }
    else if ((derivedKeyObject->keyId < UINT8_MAX) && (sss_nx_check_slot_num_valid(derivedKeyObject->keyId))) {
        outDest       = derivedKeyObject->keyId;
        hkdfData      = NULL;
        hkdfOutputLen = 0;
    }
    else {
        LOG_E("Derived key object is neither on host, nor points to slot in nx");
        goto exit;
    }

    status = nx_CryptoRequest_HKDF(&context->session->s_ctx,
        hkdfOperation,
        digestOperation,
        context->keyObject->keyId,
        0,
        saltSrc,
        saltData,
        saltDataLen,
        kSE_CryptoDataSrc_CommandBuf,
        info,
        infoLen,
        outDest,
        deriveDataLen,
        hkdfData,
        &hkdfOutputLen);
    ENSURE_OR_GO_EXIT(SM_OK == status);

    if (derivedKeyObject->keyStore->session->subsystem == kType_SSS_mbedTLS ||
        derivedKeyObject->keyStore->session->subsystem == kType_SSS_OpenSSL) {
        ENSURE_OR_GO_EXIT(
            kStatus_SSS_Success ==
            sss_key_store_set_key(
                derivedKeyObject->keyStore, derivedKeyObject, hkdfOutput, hkdfOutputLen, (hkdfOutputLen * 8), NULL, 0));
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

/* ************************************************************************** */
/* Functions : nx_nx_mac                                                  */
/* ************************************************************************** */

sss_status_t sss_nx_mac_context_init(sss_nx_mac_t *context,
    sss_nx_session_t *session,
    sss_nx_object_t *keyObject,
    sss_algorithm_t algorithm,
    sss_mode_t mode)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context)
    context->session   = session;
    context->keyObject = keyObject;
    context->algorithm = algorithm;
    context->mode      = mode;

    retval = kStatus_SSS_Success;

exit:
    return retval;
}

sss_status_t sss_nx_mac_one_go(
    sss_nx_mac_t *context, const uint8_t *message, size_t messageLen, uint8_t *mac, size_t *macLen)
{
    sss_status_t retval     = kStatus_SSS_Fail;
    smStatus_t status       = SM_NOT_OK;
    uint8_t digestOperation = kSE_DigestMode_SHA256;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(NULL != message);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(context->keyObject->keyId <= UINT8_MAX);

    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        uint16_t verifyResult = Nx_MAC_Verify_Fail;

        ENSURE_OR_GO_EXIT(NULL != mac);
        ENSURE_OR_GO_EXIT(NULL != macLen);
        if (context->mode == kMode_SSS_Mac) {
            status = nx_CryptoRequest_AES_CMAC_Sign(&context->session->s_ctx,
                Nx_MAC_Operation_OneShot,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                message,
                messageLen,
                mac,
                macLen);
            ENSURE_OR_GO_EXIT(SM_OK == status);
        }
        else if (context->mode == kMode_SSS_Mac_Validate) {
            status = nx_CryptoRequest_AES_CMAC_Verify(&context->session->s_ctx,
                Nx_MAC_Operation_OneShot,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                message,
                messageLen,
                mac,
                *macLen,
                &verifyResult);
            ENSURE_OR_GO_EXIT(SM_OK == status);

            ENSURE_OR_GO_EXIT(Nx_MAC_Verify_OK == verifyResult);
        }
        else {
            LOG_E("Unknown mode");
            goto exit;
        }
    }
    else {
        switch (context->algorithm) {
        case kAlgorithm_SSS_HMAC_SHA256: {
            digestOperation = kSE_DigestMode_SHA256;
        } break;
        case kAlgorithm_SSS_HMAC_SHA384: {
            digestOperation = kSE_DigestMode_SHA384;
        } break;
        default: {
            LOG_E("Unknown algorithm");
            goto exit;
        }
        }

        if (context->mode == kMode_SSS_Mac) {
            status = nx_CryptoRequest_HMAC_Sign(&context->session->s_ctx,
                Nx_MAC_Operation_OneShot,
                digestOperation,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                message,
                messageLen,
                kSE_CryptoDataSrc_CommandBuf,
                mac,
                macLen);
            ENSURE_OR_GO_EXIT(SM_OK == status);
        }
        else if (context->mode == kMode_SSS_Mac_Validate) {
            uint16_t verifyResult;

            ENSURE_OR_GO_EXIT(mac);
            ENSURE_OR_GO_EXIT(macLen);
            status = nx_CryptoRequest_HMAC_Verify(&context->session->s_ctx,
                Nx_MAC_Operation_OneShot,
                digestOperation,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                message,
                messageLen,
                mac,
                *macLen,
                &verifyResult);
            ENSURE_OR_GO_EXIT(SM_OK == status);
            ENSURE_OR_GO_EXIT(Nx_MAC_Verify_OK == verifyResult);
        }
        else {
            LOG_E("Unknown mode");
            goto exit;
        }
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_mac_init(sss_nx_mac_t *context)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);

    context->init_done = 0;
    // Do nothing. Call init with data in mac_update

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_mac_update(sss_nx_mac_t *context, const uint8_t *message, size_t messageLen)
{
    sss_status_t retval     = kStatus_SSS_Fail;
    smStatus_t status       = SM_NOT_OK;
    uint8_t digestOperation = kSE_DigestMode_SHA256;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(NULL != message);
    ENSURE_OR_GO_EXIT(context->keyObject->keyId <= UINT8_MAX);

    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        Nx_MAC_Operation_t operation = Nx_MAC_Operation_NA;

        if (context->init_done == 0) {
            operation          = Nx_MAC_Operation_Initialize;
            context->init_done = 1;
        }
        else {
            operation = Nx_MAC_Operation_Update;
        }

        if (context->mode == kMode_SSS_Mac) {
            status = nx_CryptoRequest_AES_CMAC_Sign(&context->session->s_ctx,
                operation,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                message,
                messageLen,
                NULL,
                NULL);
            ENSURE_OR_GO_EXIT(SM_OK == status);
        }
        else if (context->mode == kMode_SSS_Mac_Validate) {
            status = nx_CryptoRequest_AES_CMAC_Verify(&context->session->s_ctx,
                operation,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                message,
                messageLen,
                NULL,
                0,
                NULL);
            ENSURE_OR_GO_EXIT(SM_OK == status);
        }
        else {
            LOG_E("Unknown mode");
            goto exit;
        }
    }
    else {
        Nx_MAC_Operation_t operation = Nx_MAC_Operation_NA;
        switch (context->algorithm) {
        case kAlgorithm_SSS_HMAC_SHA256: {
            digestOperation = kSE_DigestMode_SHA256;
        } break;
        case kAlgorithm_SSS_HMAC_SHA384: {
            digestOperation = kSE_DigestMode_SHA384;
        } break;
        default: {
            LOG_E("Unknown algorithm");
            goto exit;
        }
        }

        if (context->init_done == 0) {
            operation          = Nx_MAC_Operation_Initialize;
            context->init_done = 1;
        }
        else {
            operation = Nx_MAC_Operation_Update;
        }

        if (context->mode == kMode_SSS_Mac) {
            status = nx_CryptoRequest_HMAC_Sign(&context->session->s_ctx,
                operation,
                digestOperation,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                message,
                messageLen,
                kSE_CryptoDataSrc_CommandBuf,
                NULL,
                NULL);
            ENSURE_OR_GO_EXIT(SM_OK == status);
        }
        else if (context->mode == kMode_SSS_Mac_Validate) {
            status = nx_CryptoRequest_HMAC_Verify(&context->session->s_ctx,
                operation,
                digestOperation,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                message,
                messageLen,
                NULL,
                0,
                NULL);
            ENSURE_OR_GO_EXIT(SM_OK == status);
        }
        else {
            LOG_E("Unknown mode");
            goto exit;
        }
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

sss_status_t sss_nx_mac_finish(sss_nx_mac_t *context, uint8_t *mac, size_t *macLen)
{
    sss_status_t retval     = kStatus_SSS_Fail;
    smStatus_t status       = SM_NOT_OK;
    uint8_t digestOperation = kSE_DigestMode_SHA256;

    ENSURE_OR_GO_EXIT(NULL != context);
    ENSURE_OR_GO_EXIT(NULL != context->keyObject);
    ENSURE_OR_GO_EXIT(NULL != context->session);
    ENSURE_OR_GO_EXIT(context->keyObject->keyId <= UINT8_MAX);

    if (context->algorithm == kAlgorithm_SSS_CMAC_AES) {
        uint16_t verifyResult = Nx_MAC_Verify_Fail;

        ENSURE_OR_GO_EXIT(mac);
        ENSURE_OR_GO_EXIT(macLen);
        if (context->mode == kMode_SSS_Mac) {
            status = nx_CryptoRequest_AES_CMAC_Sign(&context->session->s_ctx,
                Nx_MAC_Operation_Finish,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                NULL,
                0,
                mac,
                macLen);
            ENSURE_OR_GO_EXIT(SM_OK == status);
        }
        else if (context->mode == kMode_SSS_Mac_Validate) {
            status = nx_CryptoRequest_AES_CMAC_Verify(&context->session->s_ctx,
                Nx_MAC_Operation_Finish,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                NULL,
                0,
                mac,
                *macLen,
                &verifyResult);
            ENSURE_OR_GO_EXIT(SM_OK == status);
            ENSURE_OR_GO_EXIT(Nx_MAC_Verify_OK == verifyResult);
        }
        else {
            LOG_E("Unknown mode");
            goto exit;
        }
    }
    else {
        switch (context->algorithm) {
        case kAlgorithm_SSS_HMAC_SHA256: {
            digestOperation = kSE_DigestMode_SHA256;
        } break;
        case kAlgorithm_SSS_HMAC_SHA384: {
            digestOperation = kSE_DigestMode_SHA384;
        } break;
        default: {
            LOG_E("Unknown algorithm");
            goto exit;
        }
        }

        if (context->mode == kMode_SSS_Mac) {
            status = nx_CryptoRequest_HMAC_Sign(&context->session->s_ctx,
                Nx_MAC_Operation_Finish,
                digestOperation,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                NULL,
                0,
                kSE_CryptoDataSrc_CommandBuf,
                mac,
                macLen);
            ENSURE_OR_GO_EXIT(SM_OK == status);
        }
        else if (context->mode == kMode_SSS_Mac_Validate) {
            uint16_t verifyResult;
            ENSURE_OR_GO_EXIT(mac);
            ENSURE_OR_GO_EXIT(macLen);
            status = nx_CryptoRequest_HMAC_Verify(&context->session->s_ctx,
                Nx_MAC_Operation_Finish,
                digestOperation,
                context->keyObject->keyId,
                context->keyObject->keyLen,
                kSE_CryptoDataSrc_CommandBuf,
                NULL,
                0,
                mac,
                *macLen,
                &verifyResult);
            ENSURE_OR_GO_EXIT(SM_OK == status);
            ENSURE_OR_GO_EXIT(Nx_MAC_Verify_OK == verifyResult);
        }
        else {
            LOG_E("Unknown mode");
            goto exit;
        }
    }

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

void sss_nx_mac_context_free(sss_nx_mac_t *context)
{
    if (NULL == context) {
        LOG_E("No context to free!");
    }
    else {
        memset(context, 0, sizeof(*context));
    }
}

/* End: nx_mac */

int util_replace_substring(
    char *string, char *oldSubstring, char *newSubstring, char *outputString, size_t outputStringSize)
{
    size_t i, counter = 0;
    size_t newSubstringLen = 0, oldSubstringLen = 0, newStringLen = 0;

    if ((string == NULL) || (oldSubstring == NULL) || (newSubstring == NULL) || (outputString == NULL)) {
        LOG_E("Input parameter is NULL.");
        return -1;
    }

    oldSubstringLen = strlen(oldSubstring);
    newSubstringLen = strlen(newSubstring);

    // Get the number of old substring.
    for (i = 0; string[i] != '\0'; i++) {
        if (strstr(&string[i], oldSubstring) == &string[i]) {
            if ((UINT_MAX - 1) < counter) {
                return -1;
            }
            counter++;
            if (oldSubstringLen < 1) {
                return -1;
            }
            if ((UINT_MAX - i) < (oldSubstringLen - 1)) {
                return -1;
            }
            i += oldSubstringLen - 1;
        }
    }

    // Calculate new string length and check if we have enough buffer.
    if (newSubstringLen < oldSubstringLen) {
        return -1;
    }

    if ((newSubstringLen - oldSubstringLen) >= ((UINT_MAX - i) / counter)) {
        return -1;
    }

    newStringLen = i + counter * (newSubstringLen - oldSubstringLen) + 1;
    if (newStringLen > outputStringSize) {
        LOG_E("Not enough space for new string");
        return -1;
    }

    i = 0;
    while (*string) {
        if (strstr(string, oldSubstring) == string) {
            // Find old substring, copy new substring to new string.
            strcpy(&outputString[i], newSubstring);
            if ((UINT_MAX - i) < newSubstringLen) {
                return -1;
            }
            i += newSubstringLen;
            string += oldSubstringLen;
        }
        else {
            if (i >= (outputStringSize - 1)) {
                return -1;
            }
            outputString[i++] = *string++;
        }
    }

    outputString[i] = '\0';

    return 0;
}

/******** Data transfer function ********/

#if defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER) ||     \
    defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER) || \
    defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH) ||               \
    defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
static smStatus_t sss_nx_TXn_AES_EV2(struct SeSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended,
    void *options)
{
    smStatus_t ret     = SM_NOT_OK;
    tlvHeader_t outHdr = {
        0,
    };
    uint8_t txBuf[NX_MAX_BUF_SIZE_CMD] = {
        0,
    };
    size_t txBufLen   = sizeof(txBuf);
    uint8_t cmd       = 0; // INT
    size_t maxRspLen  = 0;
    uint8_t *afRsp    = NULL; // Point to additional frame response buffer
    size_t afRspLen   = 0;
    tlvHeader_t afHdr = {0}; // Additional frame request header.

    ENSURE_OR_GO_EXIT(pSession != NULL);
    ENSURE_OR_GO_EXIT(hdr != NULL);
    ENSURE_OR_GO_EXIT((cmdHeader != NULL) || (cmdHeaderLen == 0));
    ENSURE_OR_GO_EXIT((cmdData != NULL) || (cmdDataLen == 0));
    ENSURE_OR_GO_EXIT(rsp != NULL);
    ENSURE_OR_GO_EXIT(rspLen != NULL);

    maxRspLen = *rspLen;
    cmd       = hdr->hdr[1]; // INT

    ret = pSession->fp_Transform(pSession,
        hdr,
        cmdHeader,
        cmdHeaderLen,
        cmdData,
        cmdDataLen,
        &outHdr,
        txBuf,
        &txBufLen,
        hasle,
        isExtended,
        options);
    ENSURE_OR_GO_EXIT(ret == SM_OK);

    ret = SM_NOT_OK;
    ret = pSession->fp_RawTXn(pSession->conn_ctx,
        pSession->authType,
        &outHdr,
        txBuf,
        txBufLen,
        rsp,
        rspLen,
        hasle,
        isExtended,
        options); // EV2 may includes ENC+MAC value. So Le = 1.
    ENSURE_OR_GO_EXIT(ret == SM_OK);

    // Process additional frame response
    afRsp    = rsp;
    afRspLen = *rspLen;

    if (afRspLen < 1) {
        ret = SM_NOT_OK;
        goto exit;
    }

    while (
        afRsp[afRspLen - 1] == 0xAF) { // If last respond end with 0x91AF, host should send cmd 0x90AF for next respond

        ret = SM_NOT_OK;

        ENSURE_OR_GO_EXIT(afRspLen >= 2);
        afRsp += afRspLen - 2; // Pointer to rcv buffer for next response.
        ENSURE_OR_GO_EXIT(maxRspLen >= (afRspLen - 2));
        afRspLen = maxRspLen - (afRspLen - 2); // Free buffer size for next response.

        memset(&outHdr, 0, sizeof(outHdr));
        memset(txBuf, 0, sizeof(txBuf));
        txBufLen = sizeof(txBuf);

        ret = SM_NOT_OK;
        ret = Se_Create_AdditionalFrameRequest(&afHdr);
        ENSURE_OR_GO_EXIT(ret == SM_OK);

        ret = SM_NOT_OK;
        ret = pSession->fp_Transform(
            pSession, &afHdr, NULL, 0, NULL, 0, &outHdr, txBuf, &txBufLen, hasle, isExtended, NULL);
        ENSURE_OR_GO_EXIT(ret == SM_OK);

        ret = SM_NOT_OK;
        ret = pSession->fp_RawTXn(pSession->conn_ctx,
            pSession->authType,
            &outHdr,
            txBuf,
            txBufLen,
            afRsp,
            &afRspLen,
            hasle,
            isExtended,
            options);
        ENSURE_OR_GO_EXIT(ret == SM_OK);

        if (afRspLen < 1) {
            ret = SM_NOT_OK;
            goto exit;
        }
        if ((SIZE_MAX - (*rspLen) + 2) < afRspLen) {
            ret = SM_NOT_OK;
            goto exit;
        }
        *rspLen = *rspLen - 2 + afRspLen; // Response, inlcuding SW1SW2
    }

    ret = SM_NOT_OK;
    ret = pSession->fp_DeCrypt(pSession, cmdHeaderLen + cmdDataLen, cmd, rsp, rspLen, isExtended, options);
    ENSURE_OR_GO_EXIT((ret == SM_OK) || (ret == SM_OK_ALT));

    if (ret == SM_OK_ALT) {
        ret = SM_OK;
    }

exit:
    return ret;
}
#endif // SSS_HAVE_AUTH_SIGMA_I_PROVER || SSS_HAVE_AUTH_SIGMA_I_VERIFIER

static smStatus_t sss_nx_TXn(struct SeSession *pSession,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended,
    void *options)
{
    smStatus_t ret     = SM_NOT_OK;
    tlvHeader_t outHdr = {
        0,
    };
    uint8_t txBuf[NX_MAX_BUF_SIZE_CMD] = {
        0,
    };
    size_t txBufLen   = sizeof(txBuf);
    uint8_t cmd       = 0; // INT
    size_t maxRspLen  = 0;
    uint8_t *afRsp    = NULL; // Point to additional frame response buffer
    size_t afRspLen   = 0;
    tlvHeader_t afHdr = {0}; // Additional frame request header.

    ENSURE_OR_GO_EXIT(pSession != NULL);
    ENSURE_OR_GO_EXIT(hdr != NULL);
    ENSURE_OR_GO_EXIT((cmdHeader != NULL) || (cmdHeaderLen == 0));
    ENSURE_OR_GO_EXIT((cmdData != NULL) || (cmdDataLen == 0));
    ENSURE_OR_GO_EXIT(rsp != NULL);
    ENSURE_OR_GO_EXIT(rspLen != NULL);

    maxRspLen = *rspLen;
    cmd       = hdr->hdr[1]; // INT

    ret = pSession->fp_Transform(pSession,
        hdr,
        cmdHeader,
        cmdHeaderLen,
        cmdData,
        cmdDataLen,
        &outHdr,
        txBuf,
        &txBufLen,
        hasle,
        isExtended,
        options);
    ENSURE_OR_GO_EXIT(ret == SM_OK);

    ret = SM_NOT_OK;
    ret = pSession->fp_RawTXn(
        pSession->conn_ctx, pSession->authType, &outHdr, txBuf, txBufLen, rsp, rspLen, hasle, isExtended, options);

    ENSURE_OR_GO_EXIT(ret == SM_OK);

    // Process additional frame response
    afRsp    = rsp;
    afRspLen = *rspLen;
    if (afRspLen < 1) {
        ret = SM_NOT_OK;
        goto exit;
    }

    if ((cmd == NX_INS_AUTHENTICATE_EV2_FIRST || cmd == NX_INS_AUTHENTICATE_EV2_NON_FIRST) &&
        (afRsp[afRspLen - 1] == 0xAF)) {
        return SM_OK;
    }

    while (
        afRsp[afRspLen - 1] == 0xAF) { // If last respond end with 0x91AF, host should send cmd 0x90AF for next respond

        ret = SM_NOT_OK;

        ENSURE_OR_GO_EXIT(afRspLen >= 2);
        afRsp += afRspLen - 2; // Pointer to rcv buffer for next response.

        ENSURE_OR_GO_EXIT(maxRspLen > (afRspLen + 2));
        afRspLen = maxRspLen - (afRspLen - 2); // Free buffer size for next response.

        memset(&outHdr, 0, sizeof(outHdr));
        memset(txBuf, 0, sizeof(txBuf));
        txBufLen = sizeof(txBuf);

        ret = SM_NOT_OK;
        ret = Se_Create_AdditionalFrameRequest(&afHdr);
        ENSURE_OR_GO_EXIT(ret == SM_OK);

        ret = SM_NOT_OK;
        ret = pSession->fp_Transform(
            pSession, &afHdr, NULL, 0, NULL, 0, &outHdr, txBuf, &txBufLen, hasle, isExtended, options);
        ENSURE_OR_GO_EXIT(ret == SM_OK);

        ret = SM_NOT_OK;
        ret = pSession->fp_RawTXn(pSession->conn_ctx,
            pSession->authType,
            &outHdr,
            txBuf,
            txBufLen,
            afRsp,
            &afRspLen,
            hasle,
            isExtended,
            options);
        ENSURE_OR_GO_EXIT(ret == SM_OK);

        ret = SM_NOT_OK;
        if (afRspLen < 1) {
            ret = SM_NOT_OK;
            goto exit;
        }
        if ((SIZE_MAX - (*rspLen) + 2) < afRspLen) {
            ret = SM_NOT_OK;
            goto exit;
        }
        *rspLen = *rspLen - 2 + afRspLen; // Response, inlcuding SW1SW2
    }

    ret = SM_NOT_OK;
    ret = pSession->fp_DeCrypt(pSession, cmdHeaderLen + cmdDataLen, cmd, rsp, rspLen, isExtended, options);
    ENSURE_OR_GO_EXIT((ret == SM_OK) || (ret == SM_OK_ALT));

    if (ret == SM_OK_ALT) {
        ret = SM_OK;
    }

exit:
    return ret;
}

static smStatus_t sss_nx_channel_txnRaw(void *conn_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended)
{
    uint8_t txBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    size_t i                           = 0;
    smStatus_t ret                     = SM_NOT_OK;

    if ((hdr == NULL) || (cmdBuf == NULL) || (rsp == NULL) || (rspLen == NULL)) {
        LOG_E("Tx APDU command failed: Wrong parameter.");
        goto exit;
    }

    if ((cmdBufLen >= 256) && (isExtended == 0)) {
        // Lc 1 - 255 Byte for short.
        LOG_E("Construct APDU command failed: too long command.");
        goto exit;
    }

    if ((cmdBufLen >= 65536) && (isExtended == 1)) {
        // Lc 1 - 65535 Byte for extended.
        LOG_E("Construct APDU command failed: too long command.");
        goto exit;
    }

    memcpy(&txBuf[i], hdr, sizeof(*hdr));
    i += sizeof(*hdr);

    // Lc + command
    if (cmdBufLen > 0) {
        if (isExtended == 1) {
            // Extended mode
            txBuf[i++] = 0x00;
            txBuf[i++] = 0xFFu & (cmdBufLen >> 8);
            txBuf[i++] = 0xFFu & (cmdBufLen);
        }
        else {
            // Short mode
            txBuf[i++] = (uint8_t)cmdBufLen;
        }
        ENSURE_OR_GO_EXIT((i + cmdBufLen) <= NX_MAX_BUF_SIZE_CMD);
        memcpy(&txBuf[i], cmdBuf, cmdBufLen);
        i += cmdBufLen;
    }

    // Le
    if (hasle == 1) {
        // Short Le: 0x00   // 256Bytes
        // Extended Le: 0x00 0x00   // 65536Bytes
        // Extended Le without Lc: 0x00 0x00 0x00 // 65536Bytes
        ENSURE_OR_GO_EXIT(i < (NX_MAX_BUF_SIZE_CMD));
        txBuf[i++] = 0x00;
        if (isExtended == 1) {
            if (cmdBufLen == 0) { // Lc = 0
                ENSURE_OR_GO_EXIT(i < (NX_MAX_BUF_SIZE_CMD - 1));
                txBuf[i++] = 0x00;
                txBuf[i++] = 0x00;
            }
            else {
                ENSURE_OR_GO_EXIT(i < (NX_MAX_BUF_SIZE_CMD));
                txBuf[i++] = 0x00;
            }
        }
    }

    ENSURE_OR_GO_EXIT((*rspLen) <= UINT32_MAX);
    uint32_t U32rspLen = (uint32_t)*rspLen;
    ret                = (smStatus_t)smCom_TransceiveRaw(conn_ctx, txBuf, (U16)i, rsp, &U32rspLen);
    *rspLen            = U32rspLen;

exit:
    return ret;
}

static smStatus_t sss_nx_channel_txn(void *conn_ctx,
    nx_auth_type_t currAuth,
    const tlvHeader_t *hdr,
    uint8_t *cmdBuf,
    size_t cmdBufLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended,
    void *options)
{
    smStatus_t retStatus = SM_NOT_OK;

    retStatus = sss_nx_channel_txnRaw(conn_ctx, hdr, cmdBuf, cmdBufLen, rsp, rspLen, hasle, isExtended);
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

exit:
    return retStatus;
}

static sss_status_t nx_check_input_len(size_t inLen, sss_algorithm_t algorithm)
{
    sss_status_t retval = kStatus_SSS_Fail;

    switch (algorithm) {
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_ECDSA_SHA256:
        retval = (inLen == 32) ? kStatus_SSS_Success : kStatus_SSS_Fail;
        break;
    default:
        LOG_E("Unkown algorithm");
        goto exit;
    }

    retval = kStatus_SSS_Success;

exit:
    return retval;
}

static SE_ECSignatureAlgo_t nx_get_ec_sign_hash_mode(sss_algorithm_t algorithm)
{
    SE_ECSignatureAlgo_t mode = kSE_ECSignatureAlgo_NA;
    switch (algorithm) {
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_ECDSA_SHA256:
        mode = kSE_ECSignatureAlgo_SHA_256;
        break;
    default:
        mode = kSE_ECSignatureAlgo_NA;
        break;
    }
    return mode;
}

SE_DigestMode_t nx_get_sha_algo(sss_algorithm_t algorithm)
{
    SE_DigestMode_t sha_type = kSE_DigestMode_NA;

    switch (algorithm) {
    case kAlgorithm_SSS_SHA256:
    case kAlgorithm_SSS_HMAC_SHA256:
        sha_type = kSE_DigestMode_SHA256;
        break;
    case kAlgorithm_SSS_SHA384:
    case kAlgorithm_SSS_HMAC_SHA384:
        sha_type = kSE_DigestMode_SHA384;
        break;
    default:
        break;
    }

    return sha_type;
}

static uint32_t nx_calculate_crc32(const void *pData, size_t length)
{
    uint32_t startValue = 0xFFFFFFFF;
    size_t i = 0, j = 0;

    uint8_t *pByte            = (uint8_t *)pData;
    const uint32_t polynomial = 0xEDB88320;
    uint32_t crc              = startValue;
    uint32_t temp             = 0;

    for (i = 0; i < length; ++i) {
        temp = (crc ^ pByte[i]) & 0xFF;

        // read 8 bits one at a time
        for (j = 0; j < 8; ++j) {
            if (1 == (temp & 1)) {
                temp = (temp >> 1) ^ polynomial;
            }
            else {
                temp = (temp >> 1);
            }
        }
        crc = (crc >> 8) ^ temp;
    }

    return crc;
}

static sss_status_t nx_calculate_keydata_with_crc32(const uint8_t *newKeyData,
    size_t newKeyDataLength,
    uint8_t *oldKeyData,
    size_t oldKeyDataLength,
    uint8_t keyVersion,
    uint8_t *keyData,
    size_t *keyDataLen)
{
    sss_status_t retval                     = kStatus_SSS_Fail;
    uint8_t paddedOldKey[NX_AES256_KEY_LEN] = {0};
    uint32_t crc32                          = 0;
    size_t i                                = 0;

    ENSURE_OR_GO_EXIT(NULL != newKeyData);
    ENSURE_OR_GO_EXIT(NULL != oldKeyData);
    ENSURE_OR_GO_EXIT(NULL != keyData);
    ENSURE_OR_GO_EXIT(NULL != keyDataLen);
    ENSURE_OR_GO_EXIT((oldKeyDataLength == NX_AES128_KEY_LEN) || (oldKeyDataLength == NX_AES256_KEY_LEN));
    ENSURE_OR_GO_EXIT((newKeyDataLength == NX_AES128_KEY_LEN) || (newKeyDataLength == NX_AES256_KEY_LEN));

    if (oldKeyDataLength > newKeyDataLength) {
        // Truncate old key
        memcpy(paddedOldKey, oldKeyData, newKeyDataLength);
    }
    else if (oldKeyDataLength < newKeyDataLength) {
        // Pad old key with 0
        memcpy(paddedOldKey, oldKeyData, oldKeyDataLength);
    }
    else {
        memcpy(paddedOldKey, oldKeyData, oldKeyDataLength);
    }

    ENSURE_OR_GO_EXIT((*keyDataLen) >= (newKeyDataLength + 1 + 4)); // NewKey^OldKey + KeyVer + CRC32

    memcpy(keyData, newKeyData, newKeyDataLength);
    for (i = 0; i < newKeyDataLength; i++) {
        keyData[i] ^= paddedOldKey[i];
    }

    keyData[newKeyDataLength]     = keyVersion;
    crc32                         = nx_calculate_crc32(newKeyData, newKeyDataLength);
    keyData[newKeyDataLength + 1] = (uint8_t)((crc32 & 0x000000FF) >> 0);
    keyData[newKeyDataLength + 2] = (uint8_t)((crc32 & 0x0000FF00) >> 8);
    keyData[newKeyDataLength + 3] = (uint8_t)((crc32 & 0x00FF0000) >> 16);
    keyData[newKeyDataLength + 4] = (uint8_t)((crc32 & 0xFF000000) >> 24);
    *keyDataLen                   = newKeyDataLength + 1 + 4; // Version, CRC32

    retval = kStatus_SSS_Success;
exit:
    return retval;
}

#endif /* SSS_HAVE_NX_TYPE */
//Dummy change
