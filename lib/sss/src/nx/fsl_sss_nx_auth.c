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

#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include "fsl_sss_nx_auth.h"
#include "fsl_sss_nx_auth_keys.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "fsl_sss_util_asn1_der.h"

/* *****************************************************************************************************************
* Internal Definitions
* ***************************************************************************************************************** */
#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

/* ************************************************************************** */
/* Functions : Private function declaration                                   */
/* ************************************************************************** */

/* Internal APIs for Symmetric Authentication */
#if (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
static sss_status_t nx_Tx_AuthenticateEV2First_Part1(
    pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndBBuf, size_t RndBBufLen);
static sss_status_t nx_Tx_AuthenticateEV2First_Part2(
    pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndBBuf, size_t RndBBufLen);
static sss_status_t nx_Tx_AuthenticateEV2NonFirst_Part1(
    pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndBBuf, size_t RndBBufLen);
static sss_status_t nx_Tx_AuthenticateEV2NonFirst_Part2(
    pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndBBuf, size_t RndBBufLen);
static sss_status_t host_symmetric_decrypt(
    sss_object_t *appKey, uint8_t *dataToDecrypt, size_t dataToDecryptLen, uint8_t *plaintextResponse);
static sss_status_t host_symmetric_encrypt(
    sss_object_t *appKey, uint8_t *dataToEncrypt, size_t dataToEncryptLen, uint8_t *encCmdData);
static sss_status_t host_generate_random(sss_session_t *pSession, uint8_t *rndBuf, size_t rndBufLen);
static sss_status_t host_do_mac(
    sss_object_t *appKey, uint8_t *dataToMAC, size_t dataToMACLen, uint8_t *macToAdd, size_t macLen);
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2)
static sss_status_t symm_auth_derive_AES128_session_keys(nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndA, uint8_t *RndB);
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2)
static sss_status_t symm_auth_derive_AES256_session_keys(nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndA, uint8_t *RndB);
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2
static smStatus_t convert_RndDash_To_RndBuffer(
    uint8_t *rndDash, size_t rndDashLen, uint8_t *rndBuffer, size_t *rndBufferLen);
static smStatus_t convert_RndBuffer_To_RndDash(
    uint8_t *rndBuffer, size_t rndBufferLen, uint8_t *rndDash, size_t *rndDashLen);
sss_status_t nx_prepare_host_for_auth_key_symm_auth(
    nx_auth_symm_ctx_t *pAuthCtx, sss_key_store_t *pKs, nx_connect_ctx_t *nx_conn_ctx);
#endif // SSS_HAVE_AUTH_SYMM_AUTH

/* Internal APIs for SIGMA-I Authentication */
#if (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
    (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||     \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))

static void increase_big_data(uint8_t *data, size_t byteNumber);
static sss_status_t tunnel_type_to_keySize(nx_secure_symm_type_t supportedSecureTunnelType, uint8_t *keySize);
static sss_status_t nx_verifier_Tx_init_pub_key(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *ephemDERPubkey,  // ASN.1 encoded
    size_t ephemDERPubkeyLen, // ASN.1 encoded
    uint8_t *sePubKeyBuf,
    size_t *pSePubKeyBufLen,
    uint8_t *seEncHashSigBuf,
    size_t *pSeEncHashSigBufLen);
static void set_bp256_header(uint8_t *pbKey, size_t *pbKeyByteLen);
static void set_nistp256_header(uint8_t *pbKey, size_t *pbKeyByteLen);
static sss_status_t nx_calculate_shared_secret(
    nx_auth_sigma_ctx_t *pAuthCtx, uint8_t *sharedSecret, size_t *sharedSecretLen);
static sss_status_t nx_create_kdf_key(nx_auth_sigma_ctx_t *pAuthCtx, uint8_t *transXY, size_t transXYLen);
static sss_status_t nx_set_session_key(nx_auth_sigma_ctx_t *pAuthCtx, char *label);
static sss_status_t nx_set_session_nonce(nx_auth_sigma_ctx_t *pAuthCtx, char *label);
static sss_status_t nx_generate_session_keys_and_nonce(
    nx_auth_sigma_ctx_t *pAuthCtx, uint8_t *pInitPk, uint8_t *pRspPk);
static sss_status_t nx_enc_AES256_CCM(sss_object_t *pKey,
    uint8_t *pNonce,
    size_t nonceLen,
    uint8_t *pInData,
    size_t inDataLen,
    uint8_t *pEncbuf,
    size_t *pEncbufLen,
    uint8_t *pTagBuf,
    size_t *tagLen);
static sss_status_t nx_Tx_cert_request(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    nx_cert_level_t level,
    bool host_init,
    uint8_t *rxEncCertBuf,
    size_t *rxEncCertBufLen);
static sss_status_t nx_dec_AES256_CCM(sss_object_t *pKey,
    uint8_t *pNonce,
    size_t nonceLen,
    uint8_t *pEncbuf,
    size_t encBufLen,
    uint8_t *pTagBuf,
    size_t tagLen,
    uint8_t *pPlainData,
    size_t *pPlainDataLen);
static sss_status_t nx_decrypt_certificate(nx_auth_sigma_ctx_t *pAuthCtx,
    nx_cert_level_t level,
    bool host_init,
    uint8_t *encCertBuf,
    size_t encCertBufLen,
    uint8_t *decCertBuf,
    size_t *decCertBufLen);
static sss_status_t nx_get_leaf_cert_hash(nx_auth_sigma_ctx_t *pAuthCtx,
    bool host_init,
    uint8_t *pEncHashBuf,
    size_t encHashBufLen,
    uint8_t *pDecCertHashBuf,
    size_t *pDecCertHashBufLen);
static sss_status_t nx_set_cert_pk(void *authCtx, uint8_t *key_buffer, size_t key_buffer_len);

static sss_status_t nx_verify_leaf_cert_hash(
    void *authCtx, uint8_t *certHashBuf, size_t certHashBufLen, unsigned char *certBuf, size_t certBufLen);
static sss_status_t nx_asn1_encode_signature(uint8_t *sig, size_t sigLen, uint8_t *asn1Sig, size_t *asn1SigLen);
static sss_status_t nx_verify_leaf_cert_hash_signature(nx_auth_sigma_ctx_t *pAuthCtx,
    bool host_init,
    uint8_t *certHashBuf,
    size_t certHashBufLen,
    uint8_t *certHashSigBuf,
    size_t certHashBufSigLen,
    uint8_t *initEphemPubkey,
    uint8_t *respEphemPubkey,
    size_t pubkeyLen);
#ifdef EX_SSS_SIGMA_I_CACHE_FILE_DIR
static sss_status_t nx_leaf_cert_cache_insert(void *authCtx, uint8_t *pCertHashBuf, size_t certHashBufLen);
#endif
static sss_status_t nx_decode_ASN1_signature(uint8_t *asn1Sig, size_t asn1SigLen, uint8_t *sigBuf, size_t *sigBufLen);
static sss_status_t nx_verifier_Tx_cert_hash_sig(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *hostEphemPubkey,
    uint8_t *seEphemPubkey,
    size_t pubkeyLen,
    uint8_t *rxTag,
    uint8_t *rxEncCertReqBuf,
    size_t *pRxEncCertReqBufLen);
static sss_status_t nx_decrypt_se_cert_req(nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *encCertBuf,
    size_t encCertBufLen,
    bool host_init,
    uint8_t *seCertReqBuf,
    size_t *seCertReqBufLen);
static sss_status_t nx_default_host_cert(sss_cipher_type_t curveType, int level, uint8_t *buffer, size_t *bufferLen);
static sss_status_t nx_default_se_root_cert(sss_cipher_type_t curveType, uint8_t *buffer, size_t *bufferLen);
static sss_status_t nx_get_se_root_cert(sss_cipher_type_t curveType, uint8_t *buffer, size_t *bufferLen);
static sss_status_t nx_get_host_cert(
    NX_CERTIFICATE_LEVEL_t level, sss_cipher_type_t curveType, uint8_t *buffer, size_t *bufferLen);
static sss_status_t nx_Tx_cert_reply_sig(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *rxSeCertReq,
    size_t rxSeCertReqLen,
    bool host_init,
    uint8_t *rxTag,
    uint8_t *rxEncCertReqBuf,
    size_t *pRxEncCertReqBufLen);

static sss_status_t nx_prover_Tx_control_transfer(
    pSeSession_t seSession, nx_auth_sigma_ctx_t *pAuthCtx, uint8_t *rxPubKeyBuf, size_t *pRxPubKeyBufLen);
static sss_status_t nx_prepare_host_c_k_data(nx_auth_sigma_ctx_t *pAuthCtx,
    bool host_init,
    uint8_t *hostEpemPubkeyBuf, // ASN.1 encoded
    uint8_t *seEpemPubkeyBuf,   // ASN.1 encoded
    size_t pubKeyLen,
    uint8_t *ckDataBuf,
    size_t *ckDataBufLen);
static sss_status_t nx_prover_Tx_cert_hash_sig(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *hostEpemPubkeyBuf, // ASN.1 encoded
    uint8_t *seEpemPubkeyBuf,   // ASN.1 encoded
    size_t pubKeyLen,
    uint8_t *respTag,
    uint8_t *rxEncCertReqBuf,
    size_t *pRxEncCertReqBufLen);

/* Function to Set Init and Allocate static keys and Init Allocate dynamic keys */
sss_status_t nx_prepare_host_for_auth_key_sigma_i(nx_auth_sigma_ctx_t *pAuthCtx,
    sss_key_store_t *pKs,
    sss_cipher_type_t host_cert_curve_type,
    sss_cipher_type_t host_ephem_curve_type);

/* **************************************************************************************************************** */
/* Prototypes of hostcryto auth functions                                                                                */
/* **************************************************************************************************************** */
int nx_hostcrypto_curve_type_to_group_id(sss_cipher_type_t curveType);
sss_status_t nx_hostcrypto_validate_pubkey(uint8_t *pubKeyBuf, size_t pubKeyBufLen, sss_cipher_type_t curveType);
sss_status_t nx_hostcrypto_parse_x509_cert(nx_device_cert_ctx_host_t *deviceCertCtx,
    nx_auth_cert_type_t certType,
    nx_cert_level_t certIndex,
    unsigned char *certBuf,
    size_t certBufLen);
sss_status_t nx_hostcrypto_get_CA_cert_list(nx_auth_sigma_ctx_t *pAuthCtx,
    nx_device_cert_ctx_host_t *deviceCertCtx,
    uint8_t *seRootCert,
    size_t seRootCertLen,
    uint8_t **deviceCACertCacheBuf);
sss_status_t nx_hostcrypto_get_pubkey_from_cert(
    nx_device_cert_ctx_host_t *deviceCertCtx, uint8_t *pubKeyBuf, size_t *pubKeyBufLen);
sss_status_t nx_hostcrypto_verify_x509_cert(nx_device_cert_ctx_host_t *deviceCertCtx, bool *valid);
void nx_hostcrypto_cert_init(nx_device_cert_ctx_host_t *deviceCertCtx);
sss_status_t nx_hostcrypto_push_intermediate_cert(nx_device_cert_ctx_host_t *deviceCertCtx, nx_cert_level_t certIndex);
void nx_hostcrypto_cert_free(nx_device_cert_ctx_host_t *deviceCertCtx);

/* Function pointers relevant to caching operations */
#ifdef EX_SSS_SIGMA_I_CACHE_FILE_DIR
#define EX_SSS_CACHE_FUNC_FIND_HASH ex_find_hash_in_cache
#define EX_SSS_CACHE_FUNC_GET_PUBLIC_KEY ex_get_pk_from_cache
#define EX_SSS_CACHE_FUNC_INSERT_HASH_PK ex_insert_hash_pk_to_cache
#define EX_SSS_CACHE_FUNC_GET_PARENT_CERT ex_get_parent_cert_from_cache
#define EX_SSS_CACHE_FUNC_INSET_PUBLIC_KEY ex_parent_cert_cache_insert
#else
#define EX_SSS_CACHE_FUNC_FIND_HASH NULL
#define EX_SSS_CACHE_FUNC_GET_PUBLIC_KEY NULL
#define EX_SSS_CACHE_FUNC_INSERT_HASH_PK NULL
#define EX_SSS_CACHE_FUNC_GET_PARENT_CERT NULL
#define EX_SSS_CACHE_FUNC_INSET_PUBLIC_KEY NULL
#endif

/* **************************************************************************************************************** */
/* Prototypes of caching functions                                                                                  */
/* **************************************************************************************************************** */
sss_status_t nx_prepare_host_for_auth_key_symm_auth(
    nx_auth_symm_ctx_t *pAuthCtx, sss_key_store_t *pKs, nx_connect_ctx_t *nx_conn_ctx);

sss_status_t ex_find_hash_in_cache(uint8_t *pCertHashBuf, size_t certHashBufLen, int *found);

sss_status_t ex_get_pk_from_cache(int index, uint8_t *pPublicKeyBuf, size_t *pPublicKeyBufLen);

sss_status_t ex_insert_hash_pk_to_cache(
    uint8_t *pCertHashBuf, size_t certHashBufLen, uint8_t *publicKey, size_t publicKeyLen);

sss_status_t ex_get_parent_cert_from_cache(int index, uint8_t *pCertBuf, size_t *pCertBufLen);

sss_status_t ex_parent_cert_cache_insert(uint8_t *pCertBuf, size_t certBufLen);

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
static sss_status_t read_file_from_fs(char *fileName, uint8_t *buffer, size_t *bufferLen);
static sss_status_t get_full_path_file_name(
    char *dirName, char *fileName, sss_cipher_type_t curveType, char *fullPathFileName);
static bool nx_dir_exists(const char *pathname);
#endif // EX_SSS_SIGMA_I_CERT_INCLUDE_DIR

#endif // (Any Authentication)

#if defined(_MSC_VER)
#define OS_PATH_SEPARATOR "\\"
#else
#define OS_PATH_SEPARATOR "/"
#endif

#if (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
    (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||     \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))

#if (defined SSS_HAVE_HOST_FRDMMCXA153 && SSS_HAVE_HOST_FRDMMCXA153)
// Global buffer to store root certificate
uint8_t seRootCert[NX_MAX_CERT_BUFFER_SIZE];
#endif // SSS_HAVE_HOST_FRDMMCXA153

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
static sss_status_t read_file_from_fs(char *fileName, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    FILE *fp            = NULL;
    int ret             = -1;
    size_t fileSize     = 0;
    size_t maxBufLen    = 0;

    if ((fileName == NULL) || (buffer == NULL) || (bufferLen == NULL)) {
        LOG_E("Load file with invalid parameters");
        goto exit;
    }

    maxBufLen = *bufferLen;
    if ((fp = fopen(fileName, "rb")) != NULL) {
        memset(buffer, 0, maxBufLen);
        fileSize = fread(buffer, sizeof(char), maxBufLen, fp);

        if ((fileSize == 0) || ferror(fp)) { /* fread failed */
            LOG_E("Error reading cert from %s", fileName);
            ret = fclose(fp);
            if (ret != 0) {
                goto exit;
            }
            goto exit;
        }
        else { /* fread success */
            *bufferLen = fileSize;
        }

        ret = fclose(fp);
        if (ret != 0) {
            goto exit;
        }
        LOG_I("Read file from %s", fileName);
    }
    else {
        LOG_D("Can not open file from %s", fileName);
        *bufferLen = 0;
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

static sss_status_t get_full_path_file_name(
    char *dirName, char *fileName, sss_cipher_type_t curveType, char *fullPathFileName)
{
    sss_status_t status = kStatus_SSS_Fail;
    int ret             = -1;

    ENSURE_OR_GO_EXIT(dirName != NULL);
    ENSURE_OR_GO_EXIT(fileName != NULL);
    ENSURE_OR_GO_EXIT((curveType == kSSS_CipherType_EC_BRAINPOOL) || (curveType == kSSS_CipherType_EC_NIST_P));
    ENSURE_OR_GO_EXIT(strlen(dirName) < EX_MAX_INCLUDE_DIR_LENGTH);
    ENSURE_OR_GO_EXIT(strlen(fileName) < EX_MAX_EXTRA_FILE_NAME_LENGTH);

    if (curveType == kSSS_CipherType_EC_BRAINPOOL) {
        ret = sprintf(fullPathFileName,
            "%s%s%s%s%s%s%s",
            dirName,
            OS_PATH_SEPARATOR,
            "cert_and_key",
            OS_PATH_SEPARATOR,
            "brainpool",
            OS_PATH_SEPARATOR,
            fileName);
    }
    else {
        ret = sprintf(fullPathFileName,
            "%s%s%s%s%s%s%s",
            dirName,
            OS_PATH_SEPARATOR,
            "cert_and_key",
            OS_PATH_SEPARATOR,
            "nist_p",
            OS_PATH_SEPARATOR,
            fileName);
    }

    ENSURE_OR_GO_EXIT(ret >= 0);
    status = kStatus_SSS_Success;
exit:
    return status;
}

static bool nx_dir_exists(const char *pathname)
{
    struct stat info;

    if (stat(pathname, &info) != 0) {
        return false;
    }
    else if (info.st_mode & S_IFDIR) {
        return true;
    }
    else {
        return false;
    }
}
#endif // EX_SSS_SIGMA_I_CERT_INCLUDE_DIR

static void increase_big_data(uint8_t *data, size_t byteNumber)
{
    size_t i = byteNumber;

    while (i > 0) {
        if (data[i - 1] == 0xFF) {
            data[i - 1] = 0x00;
            i--;
        }
        else {
            data[i - 1]++;
            break;
        }
    }
}

static sss_status_t tunnel_type_to_keySize(nx_secure_symm_type_t supportedSecureTunnelType, uint8_t *keySize)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(keySize != NULL);

    if (supportedSecureTunnelType == knx_SecureSymmType_AES128_AES256_NTAG) {
        *keySize = NX_SESSION_KEY_SIZE_BIT_AES256 | NX_SESSION_KEY_SIZE_BIT_AES128;
    }
    else if (supportedSecureTunnelType == knx_SecureSymmType_AES128_NTAG) {
        *keySize = NX_SESSION_KEY_SIZE_BIT_AES128;
    }
    else if (supportedSecureTunnelType == knx_SecureSymmType_AES256_NTAG) {
        *keySize = NX_SESSION_KEY_SIZE_BIT_AES256;
    }
    else {
        LOG_E("Unsupported secure tunnel type %u", supportedSecureTunnelType);
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Construct Initiator public key C-APDU.
 *                Tx C-APDU.
 *                A0 43
 *                   86 41 04 <xP, public key, 64 bytes>
 *
 * @param         seSession          SE session
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         ephemDERPubkey        Host ephem public key in DER format.
 * @param         ephemDERPubkeyLen     Host ephem public key length.
 * @param[out]    sePubKeyBuf           Received SE Public key in DER format.
 * @param[out]    pSePubKeyBufLen       Received SE Public key length.
 * @param[out]    seEncHashSigBuf       Received SE enc(hash and signature).
 * @param[out]    pSeEncHashSigBufLen   Received SE enc(hash and signature) length.
 *
 * @return        Status.
 */
static sss_status_t nx_verifier_Tx_init_pub_key(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *ephemDERPubkey,  // ASN.1 encoded
    size_t ephemDERPubkeyLen, // ASN.1 encoded
    uint8_t *sePubKeyBuf,
    size_t *pSePubKeyBufLen,
    uint8_t *seEncHashSigBuf,
    size_t *pSeEncHashSigBufLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    uint8_t *pEpemPubkeyBuf = NULL;
    size_t ephemPubkeyLen   = 0;
    tlvHeader_t hdr         = {{CLA_ISO7816, INS_GP_ISO_GENERAL_AUTHENTICATE, P1_SIGMA_I, 0}};
    uint8_t msgBuf[72]      = {0}; // 2 + 2 + 1 (keySize) + 3 + 64 (public key)
    size_t msgbufLen = 0, msgPayloadLen = 0;
    uint8_t *pMsgPayload     = &msgBuf[2];
    uint8_t *pMsg            = &msgBuf[0];
    size_t sePubKeyBufLenMax = 0, seEncHashSigBufMax = 0;
    size_t asn1ECHdrLen = 0;
    uint8_t keySize = 0, seKeySize = 0;
    int tlvRet                          = 1;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                    = &rspbuf[0];
    size_t rspbufLen                    = sizeof(rspbuf);
    smStatus_t retStatus                = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(ephemDERPubkey != NULL);
    ENSURE_OR_GO_EXIT(sePubKeyBuf != NULL);
    ENSURE_OR_GO_EXIT(pSePubKeyBufLen != NULL);
    ENSURE_OR_GO_EXIT(seEncHashSigBuf != NULL);
    ENSURE_OR_GO_EXIT(pSeEncHashSigBufLen != NULL);

    if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_BRAINPOOL) {
        asn1ECHdrLen = ASN_ECC_BP_256_HEADER_LEN;
    }
    else if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_NIST_P) {
        asn1ECHdrLen = ASN_ECC_NIST_256_HEADER_LEN;
    }
    else {
        goto exit;
    }

    hdr.hdr[3] = pAuthCtx->static_ctx.seCertRepoId; // P2 is cert repo id.

    sePubKeyBufLenMax  = *pSePubKeyBufLen;
    seEncHashSigBufMax = *pSeEncHashSigBufLen;

    ENSURE_OR_GO_EXIT(sePubKeyBufLenMax >= 65 + asn1ECHdrLen); // ASN.1 Header + 04 <yP, public key, 64 bytes>
    ENSURE_OR_GO_EXIT(seEncHashSigBufMax >= 65);               // 04 <yP, public key, 64 bytes>

    // Remove ASN.1 Header
    pEpemPubkeyBuf = ephemDERPubkey + asn1ECHdrLen;
    ENSURE_OR_GO_EXIT(ephemDERPubkeyLen > asn1ECHdrLen)
    ephemPubkeyLen = ephemDERPubkeyLen - asn1ECHdrLen;

    // message payload: 83 01 <key sizes supported>
    status = tunnel_type_to_keySize(pAuthCtx->static_ctx.supportedSecureTunnelType, &keySize);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = kStatus_SSS_Fail;

    tlvRet = TLVSET_U8("msgPayload", &pMsgPayload, &msgPayloadLen, NX_TAG_KEY_SIZE, keySize, sizeof(msgBuf) - 2);
    ENSURE_OR_GO_EXIT(0 == tlvRet);

    // message payload: 86 xx 04 <public key, 64 bytes>
    tlvRet = 1;
    tlvRet = TLVSET_u8buf("msgPayload",
        &pMsgPayload,
        &msgPayloadLen,
        NX_TAG_EPHEM_PUB_KEY,
        pEpemPubkeyBuf,
        ephemPubkeyLen,
        sizeof(msgBuf) - 2);
    ENSURE_OR_GO_EXIT(0 == tlvRet);

    // message: A0 xx <message payload>
    tlvRet = 1;
    tlvRet =
        TLVSET_u8buf("message", &pMsg, &msgbufLen, NX_TAG_MSGI_PUBLIC_KEY, &msgBuf[2], msgPayloadLen, sizeof(msgBuf));
    ENSURE_OR_GO_EXIT(0 == tlvRet);
    ENSURE_OR_GO_EXIT(msgbufLen == sizeof(msgBuf));

    retStatus = DoAPDUTxRx_s_Case4(seSession, &hdr, msgBuf, msgbufLen, NULL, 0, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        // Get OS public key
        // Get leaf cert hash and verify it.
        retStatus            = SM_NOT_OK;
        size_t rspIndex      = 0;
        uint8_t *pKeyHashSig = NULL; // Point to value field of Tag B1. ( B1 81 xx <...> )
        size_t keyHashSigLen = 0;
        tlvRet               = 1;
        tlvRet =
            tlvGet_u8bufPointer(pRspbuf, &rspIndex, rspbufLen, NX_TAG_MSGR_HASH_AND_SIG, &pKeyHashSig, &keyHashSigLen);
        ENSURE_OR_GO_EXIT(0 == tlvRet);
        if ((rspIndex + 2) == rspbufLen) { // Get SW1SW2
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
        ENSURE_OR_GO_EXIT(retStatus == SM_OK);
        rspIndex = 0;

        tlvRet = tlvGet_U8(pKeyHashSig, &rspIndex, keyHashSigLen, NX_TAG_KEY_SIZE, &seKeySize);
        ENSURE_OR_GO_EXIT(0 == tlvRet);

        pAuthCtx->dyn_ctx.seKeySize = seKeySize; // Store device supported key size.
        if (seKeySize == NX_SESSION_KEY_SIZE_BIT_AES256) {
            pAuthCtx->dyn_ctx.selectedSecureTunnelType = knx_SecureSymmType_AES256_NTAG;
            LOG_D("Select secure tunnel type AES256");
        }
        else if (seKeySize == NX_SESSION_KEY_SIZE_BIT_AES128) {
            pAuthCtx->dyn_ctx.selectedSecureTunnelType = knx_SecureSymmType_AES128_NTAG;
            LOG_D("Select secure tunnel type AES128");
        }
        else {
            LOG_E("Unsupported selected NX secure tunnel type 0x%x", seKeySize);
            goto exit;
        }
        tlvRet =
            tlvGet_u8buf(pKeyHashSig, &rspIndex, keyHashSigLen, NX_TAG_EPHEM_PUB_KEY, sePubKeyBuf, pSePubKeyBufLen);
        ENSURE_OR_GO_EXIT(0 == tlvRet);

        tlvRet = -1;
        tlvRet = tlvGet_u8buf(
            pKeyHashSig, &rspIndex, keyHashSigLen, NX_TAG_ENCRYPTED_PAYLOAD, seEncHashSigBuf, pSeEncHashSigBufLen);
        ENSURE_OR_GO_EXIT(0 == tlvRet);

        if (pAuthCtx->static_ctx.ephemKeypair.cipherType == kSSS_CipherType_EC_BRAINPOOL) {
            ENSURE_OR_GO_EXIT(*pSePubKeyBufLen == 65);
            set_bp256_header(sePubKeyBuf, pSePubKeyBufLen);
        }
        else if (pAuthCtx->static_ctx.ephemKeypair.cipherType == kSSS_CipherType_EC_NIST_P) {
            ENSURE_OR_GO_EXIT(*pSePubKeyBufLen == 65);
            set_nistp256_header(sePubKeyBuf, pSePubKeyBufLen);
        }
        else {
            LOG_E("Invalid cipher type");
            goto exit;
        }

        status = kStatus_SSS_Success;
    }

exit:
    return status;
}

static void set_bp256_header(uint8_t *pbKey, size_t *pbKeyByteLen)
{
    unsigned int i = 0;
    /* clang-format off */
    uint8_t temp[112] = { 0x30, 0x5a, 0x30, 0x14, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x02, 0x01, 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01,
        0x01, 0x07, 0x03, 0x42, 0x00 };
    /* clang-format on */

    for (i = 0; i < *pbKeyByteLen; i++) {
        temp[27 + i] = pbKey[i];
    }

    if ((UINT_MAX - (*pbKeyByteLen)) < 27) {
        return;
    }
    *pbKeyByteLen = *pbKeyByteLen + 27;
    memcpy(pbKey, temp, *pbKeyByteLen);
}

static void set_nistp256_header(uint8_t *pbKey, size_t *pbKeyByteLen)
{
    unsigned int i = 0;
    /* clang-format off */
    uint8_t temp[112] = { \
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, \
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, \
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, \
        0x42, 0x00 \
    };
    /* clang-format on */

    for (i = 0; i < *pbKeyByteLen; i++) {
        temp[26 + i] = pbKey[i];
    }

    *pbKeyByteLen = *pbKeyByteLen + 26;
    memcpy(pbKey, temp, *pbKeyByteLen);
}

/**
 * @brief         Calculate shared secret
 *
 *                shared secret = ECDH(pStatic_ctx->ephemKeypair,  pStatic_ctx->seEphemPubKey)
 *
 * @param         pAuthCtx          Context Pointer to auth context.
 * @param[in,out] sharedSecret      shared Secret data.
 * @param[in,out] sharedSecretLen   shared Secret data length.
 *
 * @return        Status of calculate seesion keys.
 */
static sss_status_t nx_calculate_shared_secret(
    nx_auth_sigma_ctx_t *pAuthCtx, uint8_t *sharedSecret, size_t *sharedSecretLen)
{
    sss_status_t status      = kStatus_SSS_Fail;
    sss_derive_key_t dervCtx = {0};
    sss_object_t shsSecretX  = {0};

    nx_auth_sigma_static_ctx_t *pStatic_ctx = NULL;
    size_t sharedSecBitLen                  = 0;

    ENSURE_OR_GO_CLEANUP(NULL != pAuthCtx);
    pStatic_ctx = &(pAuthCtx->static_ctx);

    // Create shared secret from pStatic_ctx->ephemKeypair and pStatic_ctx->seEphemPubKey
    status = sss_host_key_object_init(&shsSecretX, pStatic_ctx->seEphemPubKey.keyStore);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    // x co-ordinate of shared secret. So only 32 bytes.
    status = sss_host_key_object_allocate_handle(
        &shsSecretX, __LINE__, kSSS_KeyPart_Default, kSSS_CipherType_AES, 32, kKeyObject_Mode_Transient);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_host_derive_key_context_init(&dervCtx,
        pStatic_ctx->ephemKeypair.keyStore->session,
        &pStatic_ctx->ephemKeypair,
        kAlgorithm_SSS_ECDH,
        kMode_SSS_ComputeSharedSecret);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_host_derive_key_dh(&dervCtx, &pStatic_ctx->seEphemPubKey, &shsSecretX);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status =
        sss_host_key_store_get_key(&shsSecretX.keyStore, &shsSecretX, sharedSecret, sharedSecretLen, &sharedSecBitLen);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_MAU8_D("ECDH Key (Using Device and Host Ephemeral keys)", sharedSecret, *sharedSecretLen);

cleanup:
    if (dervCtx.session != NULL) {
        sss_host_derive_key_context_free(&dervCtx);
    }
    if (shsSecretX.keyStore != NULL) {
        sss_host_key_object_free(&shsSecretX);
    }
    return status;
}

/**
 * @brief         Calculate KDF key
 *
 *                Get KDF key: = sha256(trans_xy)
 *                        AES-256: complete 32 bytes
 *                        AES-128: first 16 bytes
 *                Store KDF key in dyn_ctx.kdfCmac.
 *
 * @param         pAuthCtx          Context Pointer to auth context.
 * @param[in,out] transXY           trans_xy data.
 * @param[in,out] transXYLen        trans_xy data length.
 *
 * @return        Status of calculate KDF keys.
 */
static sss_status_t nx_create_kdf_key(nx_auth_sigma_ctx_t *pAuthCtx, uint8_t *transXY, size_t transXYLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_digest_t md     = {0};
    uint8_t mdBuff[32]  = {0};
    size_t mdBuffLen    = sizeof(mdBuff);
    size_t keyBitLen    = 0;

    ENSURE_OR_GO_EXIT(NULL != pAuthCtx)
    ENSURE_OR_GO_EXIT(NULL != pAuthCtx->dyn_ctx.kdfCmac.keyStore)

    // derive KDF key = sha256(trans_xy)
    status = sss_host_digest_context_init(
        &md, pAuthCtx->dyn_ctx.kdfCmac.keyStore->session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_digest_one_go(&md, (const uint8_t *)transXY, transXYLen, mdBuff, &mdBuffLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    ENSURE_OR_GO_EXIT(mdBuffLen == 32);

    if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG) {
        keyBitLen = 256;
    }
    else {
        keyBitLen = 128;
    }

    status = sss_host_key_object_allocate_handle(&pAuthCtx->dyn_ctx.kdfCmac,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        keyBitLen / 8,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Set derive KDF key object
    status = sss_host_key_store_set_key(pAuthCtx->dyn_ctx.kdfCmac.keyStore,
        &pAuthCtx->dyn_ctx.kdfCmac,
        (const uint8_t *)mdBuff,
        keyBitLen / 8,
        keyBitLen,
        NULL,
        0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_D("KDF Key", mdBuff, keyBitLen / 8);

exit:
    if (md.session != NULL) {
        sss_host_digest_context_free(&md);
    }
    return status;
}

static sss_status_t nx_kdf_data(char *label,
    size_t labelLen,
    char *context,
    size_t contextLen,
    size_t kdfOutBitLen,
    uint8_t *kdfData,
    size_t *kdfDataLen)
{
    size_t index        = 0;
    size_t padLen       = 0;
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(label != NULL);
    ENSURE_OR_GO_EXIT(context != NULL);
    ENSURE_OR_GO_EXIT(kdfData != NULL);
    ENSURE_OR_GO_EXIT(kdfDataLen != NULL);
    ENSURE_OR_GO_EXIT((UINT_MAX - 5) >= labelLen);
    ENSURE_OR_GO_EXIT((UINT_MAX - labelLen - 5) >= contextLen);
    ENSURE_OR_GO_EXIT(*kdfDataLen >= (2 + labelLen + 1 + contextLen + 2));

    // [i]2 || Label || 0x00 || Context || [L]2
    kdfData[0] = 0x00; // iteration counter, it will be updated when calculating kdf
    kdfData[1] = 0x00; // iteration counter, it will be updated when calculating kdf
    index += 2;

    ENSURE_OR_GO_EXIT((*kdfDataLen) > (size_t)index);
    // Label; K_ei/K_er/K_ti/K_tr/K_ci/K_cr/IV_s/IV_ci/IV_cr/IV_ti/IV_tr/K_e2/K_m2
    memcpy(&kdfData[index], label, labelLen);
    index += labelLen;

    ENSURE_OR_GO_EXIT((*kdfDataLen) > (size_t)index);
    // 0x00
    kdfData[index] = 0x00;
    ENSURE_OR_GO_EXIT(INT_MAX > index);
    index++;

    // context; SIGMA-I/IVs/EV2
    ENSURE_OR_GO_EXIT((*kdfDataLen) > (size_t)index);
    memcpy(&kdfData[index], context, contextLen);
    index += contextLen;

    ENSURE_OR_GO_EXIT((size_t)index < ((*kdfDataLen) - 1));
    // KDF output data length
    kdfData[index++] = (uint8_t)(kdfOutBitLen >> 8);
    kdfData[index++] = (uint8_t)(kdfOutBitLen >> 0);

    // Padding to 16x Bytes
    if ((index & 0xF) != 0) {
        padLen = 16 - (index & 0xF);
        ENSURE_OR_GO_EXIT((UINT_MAX - padLen) >= 5);
        ENSURE_OR_GO_EXIT((UINT_MAX - labelLen) >= (size_t)(padLen + 5));
        ENSURE_OR_GO_EXIT((UINT_MAX - labelLen - padLen - 5) >= contextLen);
        ENSURE_OR_GO_EXIT(*kdfDataLen >= (2 + labelLen + 1 + contextLen + 2 + padLen));
        ENSURE_OR_GO_EXIT((*kdfDataLen) > (size_t)index);
        memset(&kdfData[index], 0, padLen);
        index += padLen;
    }

    // Total length of KDF data.
    *kdfDataLen = index;
    status      = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Calculate KDF
 *
 *                KDF = AES256 CMAC(key=kdfCmac, input=([i]2 || Label || 0x00 || Context || [L]2 ||Padding))
 *
 * @param         pAuthCtx          Context Pointer to auth context.
 * @param         kdfInputData      Input data.
 * @param         kdfInputDataLen   Length of input data.
 * @param[in,out] kdfOutputData     Output data = k_ei || k_er || k_ti || k_tr || k_ci || k_cr
 *                                           Or = iv_s || iv_ci || iv_cr || iv_ti || iv_tr
 * @param         kdfOutputDataLen  Length of output data.
 * @return        Status of calculate seesion keys.
 */
static sss_status_t nx_calculate_kdf(nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *kdfInputData,
    size_t kdfInputDataLen,
    uint8_t *kdfOutputData,
    size_t kdfOutputDataLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_mac_t macCtx        = {0};
    uint8_t *pOutSignature  = NULL;
    size_t outSignatureLen  = 16;
    uint8_t index           = 0;
    size_t iterNum          = 0;
    sss_session_t *pSession = NULL;
    sss_object_t *pKdfKey   = NULL;

    ENSURE_OR_GO_EXIT(NULL != pAuthCtx);
    ENSURE_OR_GO_EXIT(NULL != pAuthCtx->dyn_ctx.kdfCmac.keyStore);
    ENSURE_OR_GO_EXIT(NULL != kdfInputData);
    ENSURE_OR_GO_EXIT(NULL != kdfOutputData);

    pSession = pAuthCtx->dyn_ctx.kdfCmac.keyStore->session;
    pKdfKey  = &pAuthCtx->dyn_ctx.kdfCmac;

    // AES256 CMAC output 16 bytes. Calculate how many round required.
    ENSURE_OR_GO_EXIT((SIZE_MAX - kdfOutputDataLen) >= 15);
    iterNum = (kdfOutputDataLen + 15) / 16;
    ENSURE_OR_GO_EXIT(iterNum < 256);

    for (index = 0x01; index <= iterNum; index++) {
        kdfInputData[1] = index;

        // Calculate Session key with MAC one go
        pOutSignature = kdfOutputData + 16 * (index - 1);

        // Init MAC Context
        status = sss_host_mac_context_init(&macCtx, pSession, pKdfKey, kAlgorithm_SSS_CMAC_AES, kMode_SSS_Mac);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = sss_host_mac_one_go(&macCtx, kdfInputData, kdfInputDataLen, pOutSignature, &outSignatureLen);
        // Free MAC context
        if (macCtx.session != NULL) {
            sss_host_mac_context_free(&macCtx);
        }

        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = kStatus_SSS_Fail;
        ENSURE_OR_GO_EXIT(outSignatureLen == 16);
    }

    status = kStatus_SSS_Success;
exit:
    if (macCtx.session != NULL) {
        sss_host_mac_context_free(&macCtx);
    }
    return status;
}

/**
 * @brief         Set session keys
 *
 *                Construct KDF input data for K_xx: [i]2 || Label || 0x00 || Context || [L]2
 *                Calculate KDF for K_xx: KDF = AES256 CMAC(key=kdfCmac, input=([i]2 || Label || 0x00 || Context || [L]2))
 *                Set session keys k_xx from KDF output.
 *
 * @param         pAuthCtx  Context Pointer to auth context.
 * @param         label     Indicate which session key. K_ei/K_er/K_ti/K_tr/K_ci/K_cr/K_e2/K_m2.
 *
 * @return        Status of calculate seesion keys.
 */
static sss_status_t nx_set_session_key(nx_auth_sigma_ctx_t *pAuthCtx, char *label)
{
    sss_status_t status       = kStatus_SSS_Fail;
    size_t labelLen           = 0;
    char context[10]          = {0};
    size_t contextLen         = 0;
    uint8_t kdfInputData[32]  = {0};
    size_t kdfInputDataLen    = 0;
    size_t keyLen             = 0;
    uint8_t kdfOutputData[32] = {0};
    size_t kdfOutputDataLen   = sizeof(kdfOutputData);
    sss_object_t *pKey        = NULL;

    ENSURE_OR_GO_EXIT(NULL != pAuthCtx)

    if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG) {
        keyLen = 32; // 32 Bytes
    }
    else {
        keyLen = 16; // 16 Bytes
    }

    if (strcmp(label, "K_e1") == 0) {
        labelLen = strlen("K_e1");
        strcpy(context, "SIGMA-I");
        contextLen = strlen("SIGMA-I");
        pKey       = &pAuthCtx->dyn_ctx.k_e1;
    }
    else if (strcmp(label, "K_m1") == 0) {
        labelLen = strlen("K_m1");
        strcpy(context, "SIGMA-I");
        contextLen = strlen("SIGMA-I");
        pKey       = &pAuthCtx->dyn_ctx.k_m1;
    }
    else if (strcmp(label, "K_e2") == 0) {
        labelLen = strlen("K_e2");
        strcpy(context, "EV2");
        contextLen = strlen("EV2");
        pKey       = &pAuthCtx->dyn_ctx.k_e2;
    }
    else if (strcmp(label, "K_m2") == 0) {
        labelLen = strlen("K_m2");
        strcpy(context, "EV2");
        contextLen = strlen("EV2");
        pKey       = &pAuthCtx->dyn_ctx.k_m2;
    }
    else {
        LOG_E("Unsupported Key Label");
        goto exit;
    }

    // Construct KDF input data for K_xx
    // KDF input data: [i]2 || Label || 0x00 || Context || [L]2
    memset(kdfInputData, 0, sizeof(kdfInputData));
    kdfInputDataLen = sizeof(kdfInputData);
    status          = nx_kdf_data(label, labelLen, context, contextLen, keyLen * 8, kdfInputData, &kdfInputDataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Calculate KDF for K_xx
    // KDF = AES256 CMAC(key=kdfCmac, input=([i]2 || Label || 0x00 || Context || [L]2))
    kdfOutputDataLen = keyLen;
    status           = nx_calculate_kdf(pAuthCtx, kdfInputData, kdfInputDataLen, kdfOutputData, kdfOutputDataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D(label, kdfOutputData, kdfOutputDataLen);

    // Set session keys k_xx from KDF output.
    status = sss_host_key_store_set_key(pKey->keyStore, pKey, kdfOutputData, kdfOutputDataLen, keyLen * 8, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

/**
 * @brief         Set session nonce
 *
 *                Construct KDF input data for K_xx: [i]2 || Label || 0x00 || Context || [L]2
 *                Calculate KDF for IV_xx: KDF = AES256 CMAC(key=kdfCmac, input=([i]2 || Label || 0x00 || Context || [L]2))
 *
 * @param         pAuthCtx  Context Pointer to auth context.
 * @param         label     Indicate which session key. IV_s/IV_ci/IV_cr/IV_ti/IV_tr.
 *
 * @return        Status of calculate seesion keys.
 */
static sss_status_t nx_set_session_nonce(nx_auth_sigma_ctx_t *pAuthCtx, char *label)
{
    sss_status_t status       = kStatus_SSS_Fail;
    size_t labelLen           = 0;
    char context[10]          = {0};
    size_t contextLen         = 0;
    uint8_t kdfInputData[32]  = {0};
    size_t kdfInputDataLen    = 0;
    uint8_t kdfOutputData[32] = {0};
    size_t kdfOutputDataLen   = sizeof(kdfOutputData);
    uint8_t *pIV              = NULL;
    size_t ivLen              = 0;

    ENSURE_OR_GO_EXIT(NULL != pAuthCtx)

    if (strcmp(label, "IV_e1") == 0) {
        labelLen = strlen("IV_e1");
        strcpy(context, "IVs");
        contextLen = strlen("IVs");
        ivLen      = 13; // 32 Bytes
        pIV        = pAuthCtx->dyn_ctx.iv_e1;
    }
    else {
        LOG_E("Unsupported IV Label");
        goto exit;
    }

    // Construct KDF input data for IV_xx
    // KDF input data: [i]2 || Label || 0x00 || Context || [L]2
    memset(kdfInputData, 0, sizeof(kdfInputData));
    kdfInputDataLen = sizeof(kdfInputData);
    status          = nx_kdf_data(label, labelLen, context, contextLen, ivLen * 8, kdfInputData, &kdfInputDataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Calculate KDF for IV_xx
    // KDF = AES256 CMAC(key=kdfCmac, input=([i]2 || Label || 0x00 || Context || [L]2))
    kdfOutputDataLen = ivLen;
    status           = nx_calculate_kdf(pAuthCtx, kdfInputData, kdfInputDataLen, kdfOutputData, kdfOutputDataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D(label, kdfOutputData, kdfOutputDataLen);

    // Set session nonce iv_xx from KDF output.
    memcpy(pIV, kdfOutputData, kdfOutputDataLen);

exit:
    return status;
}

/**
 * @brief         Calculate session keys and NONCE
 *
 *                This API calculate session keys from Initiator and Responder public keys.
 *
 * @param         pAuthCtx       Context Pointer to auth context.
 * @param         pInitPk        Public key of Initiator.
 * @param         pRspPk         Public key of Responder.
 *
 * @return        Status of calculate session keys and NONCE.
 */
static sss_status_t nx_generate_session_keys_and_nonce(nx_auth_sigma_ctx_t *pAuthCtx, uint8_t *pInitPk, uint8_t *pRspPk)
{
    sss_status_t status           = kStatus_SSS_Fail;
    uint8_t transXY[32 + 64 + 64] = {0};
    uint8_t *pTransXY             = &transXY[0];
    uint8_t *shsSecretX           = pTransXY;
    size_t shsSecretXLen          = 32;
    size_t sessionKeyLen          = 0;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(pInitPk != NULL);
    ENSURE_OR_GO_EXIT(pRspPk != NULL);

    // Step 1 Create shared secret: = ECDH(pStatic_ctx->ephemKeypair,  pStatic_ctx->seEphemPubKey)
    status = nx_calculate_shared_secret(pAuthCtx, shsSecretX, &shsSecretXLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    ENSURE_OR_GO_EXIT(shsSecretXLen == 32);

    // Step 2 Construct trans_xy
    // trans_xy = (x co-ordinate of shared secret) | Init pk | Resp pk
    // (x co-ordinate of shared secret) is set in nx_create_kdf_key()
    memcpy((pTransXY + 32), pInitPk, 64);
    memcpy((pTransXY + 96), pRspPk, 64);

    // Step 3 Set KDF key: = sha256(trans_xy)
    status =
        nx_create_kdf_key(pAuthCtx, pTransXY, 32 + 64 + 64); // (x co-ordinate of shared secret) | Init pk | Resp pk
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG) {
        sessionKeyLen = 32; // 32 Bytes
    }
    else {
        sessionKeyLen = 16; // 16 Bytes
    }

    // Allocate handle for session keys according to key length.
    status = sss_host_key_object_allocate_handle(&pAuthCtx->dyn_ctx.k_e1,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        sessionKeyLen,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_key_object_allocate_handle(&pAuthCtx->dyn_ctx.k_m1,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        sessionKeyLen,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_key_object_allocate_handle(&pAuthCtx->dyn_ctx.k_e2,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        sessionKeyLen,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_key_object_allocate_handle(&pAuthCtx->dyn_ctx.k_m2,
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Default,
        kSSS_CipherType_AES,
        sessionKeyLen,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nx_set_session_key(pAuthCtx, "K_e1");
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nx_set_session_key(pAuthCtx, "K_m1");
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nx_set_session_nonce(pAuthCtx, "IV_e1");
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nx_set_session_key(pAuthCtx, "K_e2");
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nx_set_session_key(pAuthCtx, "K_m2");
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

/**
 * @brief         Calculate AES 256 CCM Enc with AAD is None
 *
 *                This API calculate AES256 CCM. AAD is assume to be none.
 *
 * @param         pKey        Key object for AES CCM.
 * @param         pNonce      Nonce data buffer.
 * @param         nonceLen    Nonce data buffer length.
 * @param         pInData     Input data buffer.
 * @param         inDataLen   Input data buffer length.
 * @param[out]    pEncbuf     Encrypted data buffer.
 * @param[in,out] pEncbufLen  Encrypted data buffer length.
 * @param[out]    pTagBuf     Tag data buffer.
 * @param[in,out] tagLen      Tag data buffer length.
 *
 * @return        Status of calculate session keys and NONCE.
 */
static sss_status_t nx_enc_AES256_CCM(sss_object_t *pKey,
    uint8_t *pNonce,
    size_t nonceLen,
    uint8_t *pInData,
    size_t inDataLen,
    uint8_t *pEncbuf,
    size_t *pEncbufLen,
    uint8_t *pTagBuf,
    size_t *tagLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_session_t *pSession = NULL;
    sss_aead_t aeadCtx      = {0};
    size_t blocksize        = 16;
    size_t i                = 0;
    size_t tempOutbufLen    = 0;
    size_t tempdataLen      = 0;
    size_t output_offset    = 0;
    size_t encbufLen;

    ENSURE_OR_GO_EXIT(NULL != pKey);
    ENSURE_OR_GO_EXIT(NULL != pKey->keyStore);
    ENSURE_OR_GO_EXIT(NULL != pNonce);
    ENSURE_OR_GO_EXIT(NULL != pInData);
    ENSURE_OR_GO_EXIT(NULL != pEncbuf);
    ENSURE_OR_GO_EXIT(NULL != pEncbufLen);
    ENSURE_OR_GO_EXIT(NULL != pTagBuf);
    ENSURE_OR_GO_EXIT(NULL != tagLen);

    encbufLen = *pEncbufLen;

    pSession = pKey->keyStore->session;
    ENSURE_OR_GO_EXIT(pSession != NULL);

    status = sss_host_aead_context_init(&aeadCtx, pSession, pKey, kAlgorithm_SSS_AES_CCM, kMode_SSS_Encrypt);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = kStatus_SSS_Fail;
    status = sss_host_aead_init(&aeadCtx, pNonce, nonceLen, *tagLen, 0, inDataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_aead_update_aad(&aeadCtx, NULL, 0); // AAD = null
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    for (i = 0; i < inDataLen; i = i + blocksize) {
        tempdataLen   = (i + blocksize > inDataLen) ? (inDataLen - i) : blocksize;
        tempOutbufLen = encbufLen - output_offset; // Unused output buffer length

        status = sss_host_aead_update(&aeadCtx, (pInData + i), tempdataLen, (pEncbuf + output_offset), &tempOutbufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        output_offset = output_offset + tempOutbufLen; // Used output buffer offset
        ENSURE_OR_GO_EXIT(encbufLen >= output_offset);
    }

    tempOutbufLen = encbufLen - output_offset;
    status        = sss_host_aead_finish(&aeadCtx, NULL, 0, (pEncbuf + output_offset), &tempOutbufLen, pTagBuf, tagLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(encbufLen >= output_offset + tempOutbufLen);
    *pEncbufLen = output_offset + tempOutbufLen;

    status = kStatus_SSS_Success;
exit:
    if (aeadCtx.session != NULL) {
        sss_host_aead_context_free(&aeadCtx);
    }
    return status;
}

/**
 * @brief         Calculate session keys and NONCE
 *
 *                This API calculate session keys from Initiator and Responder public keys.
 *
 * @param         pAuthCtx       Context Pointer to auth context.
 * @param         pInitPk        Public key of Initiator.
 * @param         pRspPk         Public key of Responder.
 *
 * @return        Status of calculate session keys and NONCE.
 */
static sss_status_t nx_Tx_cert_request(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    nx_cert_level_t level,
    bool host_init,
    uint8_t *rxEncCertBuf,
    size_t *rxEncCertBufLen)
{
    sss_status_t status                                = kStatus_SSS_Fail;
    sss_object_t *pKey                                 = NULL;
    uint8_t *pNonce                                    = NULL;
    size_t nonceLen                                    = 0;
    uint8_t cipherPayload[2 + NX_AES256_CCM_TAG_LENGH] = {0};
    size_t cipherPayloadLen                            = sizeof(cipherPayload);
    uint8_t *encbuf                                    = &cipherPayload[0];
    size_t encbufLen                                   = 2;
    uint8_t *tagBuf                                    = &cipherPayload[2];
    size_t tagLen                                      = NX_AES256_CCM_TAG_LENGH;
    uint8_t inData[2]                                  = {0x80, 0x00};
    size_t inDataLen                                   = 2;
    NX_TAG_t replyTag                                  = NX_TAG_NA;

    uint8_t cmdBuf[100] = {0};
    size_t encMsgLen = 0, certReqLen = 0;
    uint8_t *pCmdbuf                    = NULL;
    int tlvRet                          = 1;
    tlvHeader_t hdr                     = {{CLA_ISO7816, INS_GP_ISO_GENERAL_AUTHENTICATE, P1_SIGMA_I, 0}};
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                    = &rspbuf[0];
    size_t rspbufLen                    = sizeof(rspbuf);
    smStatus_t retStatus                = SM_NOT_OK;
    size_t rspIndex                     = 0;

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(rxEncCertBuf != NULL);
    ENSURE_OR_GO_EXIT(rxEncCertBufLen != NULL);

    // Init cert request data
    if (level == NX_CERT_LEVEL_LEAF) {
        inData[0] = 0x80;
        LOG_D("Tx leaf cert request");
    }
    else if (level == NX_CERT_LEVEL_P1) {
        inData[0] = 0x81;
        LOG_D("Tx P1 cert request");
    }
    else if (level == NX_CERT_LEVEL_P2) {
        inData[0] = 0x82;
        LOG_D("Tx P2 cert request");
    }
    else {
        goto exit;
    }

    hdr.hdr[3] = pAuthCtx->static_ctx.seCertRepoId; // P2 is cert repo id.

    pKey     = &pAuthCtx->dyn_ctx.k_e1;
    pNonce   = pAuthCtx->dyn_ctx.iv_e1;
    nonceLen = sizeof(pAuthCtx->dyn_ctx.iv_e1);

    // AES CCM on "cert request" (Initiator)
    status = nx_enc_AES256_CCM(pKey, pNonce, nonceLen, inData, inDataLen, encbuf, &encbufLen, tagBuf, &tagLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // pAuthCtx->dyn_ctx.iv_e1++/iv_ci++;
    increase_big_data(pNonce, nonceLen);

    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(encbufLen == 2);
    ENSURE_OR_GO_EXIT(tagLen == NX_AES256_CCM_TAG_LENGH);

    if (host_init == true) {
        // A2 0C                                - cert request message
        //    87 0A <AES CCM on "cert request"> - encrpyted message
        pCmdbuf   = &cmdBuf[2];
        encMsgLen = 0;
        // encrpyted message: 87 xx <message payload>
        tlvRet = TLVSET_u8buf("enc msg",
            &pCmdbuf,
            &encMsgLen,
            NX_TAG_ENCRYPTED_PAYLOAD,
            &cipherPayload[0],
            cipherPayloadLen,
            sizeof(cmdBuf) - 2);
        ENSURE_OR_GO_EXIT(0 == tlvRet)

        pCmdbuf    = &cmdBuf[0];
        certReqLen = 0;
        tlvRet     = 1;
        tlvRet     = TLVSET_u8buf(
            "cert req", &pCmdbuf, &certReqLen, NX_TAG_MSGI_CERT_REQUEST, &cmdBuf[2], encMsgLen, sizeof(cmdBuf));
        ENSURE_OR_GO_EXIT(0 == tlvRet)
    }
    else {
        // B2 0C                                - cert request message
        //    87 0A <AES CCM on "cert request"> - encrpyted message
        pCmdbuf   = &cmdBuf[2];
        encMsgLen = 0;
        // encrpyted message: 87 xx <message payload>
        tlvRet = TLVSET_u8buf("enc msg",
            &pCmdbuf,
            &encMsgLen,
            NX_TAG_ENCRYPTED_PAYLOAD,
            &cipherPayload[0],
            cipherPayloadLen,
            sizeof(cmdBuf) - 2);
        ENSURE_OR_GO_EXIT(0 == tlvRet)

        pCmdbuf    = &cmdBuf[0];
        certReqLen = 0;
        tlvRet     = 1;
        tlvRet     = TLVSET_u8buf(
            "cert req", &pCmdbuf, &certReqLen, NX_TAG_MSGR_CERT_REQUEST, &cmdBuf[2], encMsgLen, sizeof(cmdBuf));
        ENSURE_OR_GO_EXIT(0 == tlvRet)
    }

    retStatus = DoAPDUTxRx_s_Case4_ext(seSession, &hdr, cmdBuf, certReqLen, NULL, 0, rspbuf, &rspbufLen, NULL);
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    if (host_init == true) {
        replyTag = NX_TAG_MSGR_CERT_REPLY;
    }
    else {
        replyTag = NX_TAG_MSGI_CERT_REPLY;
    }

    // Get SE encrypted certificate
    retStatus = SM_NOT_OK;
    tlvRet    = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, replyTag, rxEncCertBuf, rxEncCertBufLen);
    ENSURE_OR_GO_EXIT(0 == tlvRet)
    if ((rspIndex + 2) == rspbufLen) {
        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
    }
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Calculate AES 256 CCM Enc with AAD is None
 *
 *                This API calculate AES256 CCM. AAD is assume to be none.
 *
 * @param         pKey        Key object for AES CCM.
 * @param         pNonce      Nonce data buffer.
 * @param         nonceLen    Nonce data buffer length.
 * @param         pInData     Input data buffer.
 * @param         inDataLen   Input data buffer length.
 * @param[out]    pEncbuf     Encrypted data buffer.
 * @param[in,out] pEncbufLen  Encrypted data buffer length.
 * @param[out]    pTagBuf     Tag data buffer.
 * @param[in,out] tagLen      Tag data buffer length.
 *
 * @return        Status of calculate session keys and NONCE.
 */
static sss_status_t nx_dec_AES256_CCM(sss_object_t *pKey,
    uint8_t *pNonce,
    size_t nonceLen,
    uint8_t *pEncbuf,
    size_t encBufLen,
    uint8_t *pTagBuf,
    size_t tagLen,
    uint8_t *pPlainData,
    size_t *pPlainDataLen)
{
    sss_status_t status     = kStatus_SSS_Fail;
    sss_session_t *pSession = NULL;
    sss_aead_t aeadCtx      = {0};
    size_t blocksize        = 16;
    size_t i                = 0;
    size_t tempOutbufLen    = 0;
    size_t tempdataLen      = 0;
    size_t output_offset    = 0;
    size_t plainDataLen     = 0;

    ENSURE_OR_GO_EXIT(NULL != pKey);
    ENSURE_OR_GO_EXIT(NULL != pKey->keyStore);
    ENSURE_OR_GO_EXIT(NULL != pNonce);
    ENSURE_OR_GO_EXIT(NULL != pPlainData);
    ENSURE_OR_GO_EXIT(NULL != pPlainDataLen);
    ENSURE_OR_GO_EXIT(NULL != pEncbuf);
    ENSURE_OR_GO_EXIT(NULL != pTagBuf);
    ENSURE_OR_GO_EXIT(*pPlainDataLen >= encBufLen);

    plainDataLen = *pPlainDataLen;

    pSession = pKey->keyStore->session;
    ENSURE_OR_GO_EXIT(pSession != NULL);

    status = sss_host_aead_context_init(&aeadCtx, pSession, pKey, kAlgorithm_SSS_AES_CCM, kMode_SSS_Decrypt);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_aead_init(&aeadCtx, pNonce, nonceLen, tagLen, 0, encBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_aead_update_aad(&aeadCtx, NULL, 0); // AAD = null
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    for (i = 0; i < encBufLen; i = i + blocksize) {
        tempdataLen   = (i + blocksize > encBufLen) ? (encBufLen - i) : blocksize;
        tempOutbufLen = plainDataLen - output_offset; // Unused output buffer length

        status =
            sss_host_aead_update(&aeadCtx, (pEncbuf + i), tempdataLen, (pPlainData + output_offset), &tempOutbufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        output_offset = output_offset + tempOutbufLen; // Used output buffer offset
        ENSURE_OR_GO_EXIT(plainDataLen >= output_offset);
    }

    tempOutbufLen = plainDataLen - output_offset;
    status = sss_host_aead_finish(&aeadCtx, NULL, 0, (pPlainData + output_offset), &tempOutbufLen, pTagBuf, &tagLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(plainDataLen >= output_offset + tempOutbufLen);
    *pPlainDataLen = output_offset + tempOutbufLen;

    status = kStatus_SSS_Success;
exit:
    if (aeadCtx.session != NULL) {
        sss_host_aead_context_free(&aeadCtx);
    }
    return status;
}

/**
 * @brief         Get responder certificate from encrypted cert reply.
 *
 *                This API decrpyt cert reply and remove tag. Only return cert.
 *
 * @param         pAuthCtx       Context Pointer to auth context.
 * @param         level          Leaf/P1/P2 certificate
 * @param         host_init      Host is initiator or responder.
 * @param         encCertBuf     Encrypted cert reply.
 * @param         encCertBufLen  Encrypted cert reply length.
 * @param[out]    decCertBuf     Cert.
 * @param[out]    decCertBufLen  Cert length.
 * @return        Status of calculate session keys and NONCE.
 */
static sss_status_t nx_decrypt_certificate(nx_auth_sigma_ctx_t *pAuthCtx,
    nx_cert_level_t level,
    bool host_init,
    uint8_t *encCertBuf,
    size_t encCertBufLen,
    uint8_t *decCertBuf,
    size_t *decCertBufLen)
{
    sss_status_t status       = kStatus_SSS_Fail;
    sss_object_t *pKey        = NULL;
    uint8_t *pNonce           = NULL;
    size_t nonceLen           = 0;
    size_t encBufLen          = 0;
    uint8_t *tagBuf           = NULL;
    size_t tagLen             = NX_AES256_CCM_TAG_LENGH;
    uint8_t decReplyBuf[1024] = {0};
    size_t decReplyBufLen     = sizeof(decReplyBuf);
    int tlvRet                = 0;
    size_t rspIndex           = 0;
    NX_TAG_t certTag          = NX_TAG_NA;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(encCertBuf != NULL);
    ENSURE_OR_GO_EXIT(encCertBufLen > NX_AES256_CCM_TAG_LENGH);
    encBufLen = encCertBufLen - NX_AES256_CCM_TAG_LENGH;
    tagBuf    = &encCertBuf[encCertBufLen - NX_AES256_CCM_TAG_LENGH];

    if (host_init == true) {
        pKey     = &pAuthCtx->dyn_ctx.k_e1;
        pNonce   = pAuthCtx->dyn_ctx.iv_e1;
        nonceLen = sizeof(pAuthCtx->dyn_ctx.iv_e1);
    }
    else {
        pKey     = &pAuthCtx->dyn_ctx.k_e1;
        pNonce   = pAuthCtx->dyn_ctx.iv_e1;
        nonceLen = sizeof(pAuthCtx->dyn_ctx.iv_e1);
    }

    // AES CCM on "cert request"
    status =
        nx_dec_AES256_CCM(pKey, pNonce, nonceLen, encCertBuf, encBufLen, tagBuf, tagLen, decReplyBuf, &decReplyBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // pAuthCtx->dyn_ctx.iv_e1++/iv_ci++;
    increase_big_data(pNonce, nonceLen);

    // Decrypted certificate
    // uncompressed cert: 7F 21 <length> <cert>
    // compressed cert:   7F 22 <length> <comp-cert>
    ENSURE_OR_GO_EXIT(decReplyBuf[0] == 0x7F);
    ENSURE_OR_GO_EXIT((decReplyBuf[1] == NX_TAG_UNCOMPRESSED_CERT) || (decReplyBuf[1] == NX_TAG_COMPRESSED_CERT));
    ENSURE_OR_GO_EXIT(decReplyBufLen >= 1);
    if (decReplyBuf[1] == NX_TAG_UNCOMPRESSED_CERT) {
        // Uncompressed cert.
        certTag = (NX_TAG_t)(decReplyBuf[1]);
        tlvRet  = tlvGet_u8buf(&decReplyBuf[1], &rspIndex, decReplyBufLen - 1, certTag, decCertBuf, decCertBufLen);
        ENSURE_OR_GO_EXIT(tlvRet == 0);
        ENSURE_OR_GO_EXIT(rspIndex == decReplyBufLen - 1);
    }
    else {
        LOG_E("Compressed certificate not supported");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Get leaf cert hash and signature
 *
 *                Descrypt cert hash and signature R-APDU.
 *
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         host_init             Host is initiator or responder.
 * @param         pEncHashBuf           Encrypted cert hash and signature buffer.
 * @param         encHashBufLen         Encrypted cert hash and signature buffer length.
 * @param[out]    pDecCertHashBuf       Decrypted cert hash and signature buffer.
 * @param[out]    pDecCertHashBufLen    Decrypted cert hash and signature buffer lenght.
 *
 * @return        Status of calculate session keys and NONCE.
 */
static sss_status_t nx_get_leaf_cert_hash(nx_auth_sigma_ctx_t *pAuthCtx,
    bool host_init,
    uint8_t *pEncHashBuf,
    size_t encHashBufLen,
    uint8_t *pDecCertHashBuf,
    size_t *pDecCertHashBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t *pKey  = NULL;
    uint8_t *pNonce     = NULL;
    size_t nonceLen     = 0;
    size_t encBufLen    = 0;
    uint8_t *tagBuf     = NULL;
    size_t tagLen       = NX_AES256_CCM_TAG_LENGH;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(pEncHashBuf != NULL);
    ENSURE_OR_GO_EXIT(encHashBufLen > NX_AES256_CCM_TAG_LENGH);
    ENSURE_OR_GO_EXIT(pDecCertHashBuf != NULL);
    ENSURE_OR_GO_EXIT(pDecCertHashBufLen != NULL);

    encBufLen = encHashBufLen - NX_AES256_CCM_TAG_LENGH;
    tagBuf    = &pEncHashBuf[encHashBufLen - NX_AES256_CCM_TAG_LENGH];
    pKey      = &pAuthCtx->dyn_ctx.k_e1;
    pNonce    = pAuthCtx->dyn_ctx.iv_e1;
    nonceLen  = sizeof(pAuthCtx->dyn_ctx.iv_e1);

    // AES CCM decrypt on "encrypted hash and signature"
    status = nx_dec_AES256_CCM(
        pKey, pNonce, nonceLen, pEncHashBuf, encBufLen, tagBuf, tagLen, pDecCertHashBuf, pDecCertHashBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    increase_big_data(pNonce, nonceLen);
exit:
    return status;
}

/**
 * @brief         Parse ASN.1 public key and set public key.
 *
 *                Parse ASN.1 public key and get public key curves type.
 *                Set public key to key object.
 *
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         key_buffer            ASN.1 public key.
 * @param         key_buffer_len        ASN.1 public key length.
 *
 * @return        Status of searching.
 */
static sss_status_t nx_set_cert_pk(void *authCtx, uint8_t *key_buffer, size_t key_buffer_len)
{
    uint8_t *p = NULL, *end = NULL;
    size_t len                    = 0;
    int ret                       = 1;
    sss_status_t status           = kStatus_SSS_Fail;
    uint8_t ecPublicKey_oid[]     = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}; // ecPublicKey 1.2.840.10045.2.1
    uint8_t brainpoolP256r1_oid[] = {
        0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}; // brainpoolP256r1 1.3.36.3.3.2.8.1.1.7
    uint8_t prime256v1_oid[]      = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}; // prime256v1 1.2.840.10045.3.1.7
    sss_cipher_type_t cipher_type = kSSS_CipherType_NONE;
    nx_auth_sigma_ctx_t *pAuthCtx = (nx_auth_sigma_ctx_t *)authCtx;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(key_buffer != NULL);

    p   = key_buffer;
    len = key_buffer_len;
    end = p + len;

    // SEQ
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
        LOG_E("Public key 1st SEQ error");
        goto exit;
    }

    // SEQ
    ret = 1;
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
        LOG_E("Public key 2nd SEQ error");
        goto exit;
    }

    // Obj ID: public key
    ret = 1;
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_OID)) != 0) {
        LOG_E("Public key obj id error");
        goto exit;
    }

    if ((len != sizeof(ecPublicKey_oid)) || (memcmp(p, &ecPublicKey_oid[0], len) != 0)) {
        LOG_E("PKCS7 CERT obj id is not 1.2.840.113549.1.7.2(signedData)");
        goto exit;
    }

    // Obj ID: curves
    p   = p + len;
    ret = 1;
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_OID)) != 0) {
        LOG_E("Public key obj id error");
        goto exit;
    }

    if ((len == sizeof(brainpoolP256r1_oid)) && (memcmp(p, &brainpoolP256r1_oid[0], len) == 0)) {
        // Brain pool 256 Curves.
        cipher_type = kSSS_CipherType_EC_BRAINPOOL;
    }
    else if ((len == sizeof(prime256v1_oid)) && (memcmp(p, &prime256v1_oid[0], len) == 0)) {
        // NIST-P 256 Curves
        cipher_type = kSSS_CipherType_EC_NIST_P;
    }
    else {
        LOG_E("PKCS7 CERT obj id is not 1.2.840.113549.1.7.2(signedData)");
        goto exit;
    }

    status = sss_host_key_object_allocate_handle(&(pAuthCtx->static_ctx.seLeafCertPubKey),
        MAKE_TEST_ID(__LINE__),
        kSSS_KeyPart_Public,
        cipher_type,
        64,
        kKeyObject_Mode_Transient);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Set SE certifiacate public key
    status = sss_host_key_store_set_key(pAuthCtx->static_ctx.seLeafCertPubKey.keyStore,
        &(pAuthCtx->static_ctx.seLeafCertPubKey),
        key_buffer,
        key_buffer_len,
        256,
        NULL,
        0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}

/**
 * @brief         Verify hash of leaf certificate.
 *
 *                Calculate SHA256 of leaf certificate and compared to the received one.
 *
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         certHashBuf           Cert hash buffer.
 * @param         certHashBufLen        Cert hash buffer length.
 * @param         certBuf               Cert buffer.
 * @param         certBufLen            Cert buffer length.
 *
 * @return        Status of searching.
 */
static sss_status_t nx_verify_leaf_cert_hash(
    void *authCtx, uint8_t *certHashBuf, size_t certHashBufLen, unsigned char *certBuf, size_t certBufLen)
{
    sss_status_t status                = kStatus_SSS_Fail;
    sss_digest_t md                    = {0};
    uint8_t mdCert[NX_SHA256_BYTE_LEN] = {0};
    size_t mdCertLen                   = sizeof(mdCert);
    nx_auth_sigma_ctx_t *pAuthCtx      = NULL;

    ENSURE_OR_GO_EXIT(authCtx != NULL);
    ENSURE_OR_GO_EXIT(certHashBuf != NULL);
    ENSURE_OR_GO_EXIT(certBuf != NULL);
    pAuthCtx = (nx_auth_sigma_ctx_t *)authCtx;

    status = sss_host_digest_context_init(
        &md, pAuthCtx->static_ctx.seLeafCertPubKey.keyStore->session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_digest_one_go(&md, (const uint8_t *)certBuf, certBufLen, mdCert, &mdCertLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if ((certHashBufLen != mdCertLen) || (memcmp(certHashBuf, mdCert, certHashBufLen) != 0)) {
        status = kStatus_SSS_Fail;
        LOG_E("Received hash doesn't match received leaf certificate.");
        goto exit;
    }
    else {
        LOG_D("Received hash match received leaf certificate.");
    }

exit:
    if (md.session != NULL) {
        sss_host_digest_context_free(&md);
    }
    return status;
}

/**
 * @brief         Encode signature in ASN.1 format. (Normal -> ASN.1)
 *
 *                ASN.1 encoded signature
 *                30 44
 *                   02 20 [32 bytes]
 *                   02 20 [32 bytes]
 *             Or 30 45
 *                   02 21 00 [32 bytes] (Highest bit is 1)
 *                   02 20 [32 bytes]
 *             Or 30 45
 *                   02 20 [32 bytes]
 *                   02 21 00 [32 bytes] (Highest bit is 1)
 *             Or 30 46
 *                   02 21 00 [32 bytes] (Highest bit is 1)
 *                   02 21 00 [32 bytes] (Highest bit is 1)
 *
 * @param         sig              Signature buffer.
 * @param         sigLen           Signature buffer length.
 * @param[out]    asn1Sig          ASN.1 coded signature buffer.
 * @param[out]    asn1SigLen       ASN.1 coded signature buffer length.
 *
 * @return        Status of searching.
 */
static sss_status_t nx_asn1_encode_signature(uint8_t *sig, size_t sigLen, uint8_t *asn1Sig, size_t *asn1SigLen)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(sig != NULL);
    ENSURE_OR_GO_EXIT(asn1Sig != NULL);
    ENSURE_OR_GO_EXIT(sigLen == 64);
    ENSURE_OR_GO_EXIT(*asn1SigLen >= 72);

    asn1Sig[0] = 0x30; // SEQ
    if ((sig[0] & 0x80) && (sig[32] & 0x80)) {
        /*
         *  30 46
         *     02 21 00 [32 bytes] (Highest bit is 1)
         *     02 21 00 [32 bytes] (Highest bit is 1)
         */
        asn1Sig[1] = 0x46; // LEN
        asn1Sig[2] = 0x02; // INT
        asn1Sig[3] = 0x21; // LEN
        asn1Sig[4] = 0x00; // LEN
        memcpy(&asn1Sig[5], &sig[0], 0x20);
        asn1Sig[37] = 0x02; // INT
        asn1Sig[38] = 0x21; // LEN
        asn1Sig[39] = 0x00; // LEN
        memcpy(&asn1Sig[40], &sig[32], 0x20);

        *asn1SigLen = 72;
    }
    else if ((sig[0] & 0x80) && (!(sig[32] & 0x80))) {
        /*
         *  30 45
         *     02 21 00 [32 bytes] (Highest bit is 1)
         *     02 20 [32 bytes]
         */
        asn1Sig[1] = 0x45; // LEN
        asn1Sig[2] = 0x02; // INT
        asn1Sig[3] = 0x21; // LEN
        asn1Sig[4] = 0x00; // LEN
        memcpy(&asn1Sig[5], &sig[0], 0x20);
        asn1Sig[37] = 0x02; // INT
        asn1Sig[38] = 0x20; // LEN
        memcpy(&asn1Sig[39], &sig[32], 0x20);

        *asn1SigLen = 71;
    }
    else if ((!(sig[0] & 0x80)) && (sig[32] & 0x80)) {
        /*
         *  30 45
         *     02 20 [32 bytes]
         *     02 21 00 [32 bytes] (Highest bit is 1)
         */
        asn1Sig[1] = 0x45; // LEN
        asn1Sig[2] = 0x02; // INT
        asn1Sig[3] = 0x20; // LEN
        memcpy(&asn1Sig[4], &sig[0], 0x20);
        asn1Sig[36] = 0x02; // INT
        asn1Sig[37] = 0x21; // LEN
        asn1Sig[38] = 0x00; // LEN
        memcpy(&asn1Sig[39], &sig[32], 0x20);

        *asn1SigLen = 71;
    }
    else {
        /*
         *  30 45
         *     02 20 [32 bytes]
         *     02 20 [32 bytes]
         */
        asn1Sig[1] = 0x44; // LEN
        asn1Sig[2] = 0x02; // INT
        asn1Sig[3] = 0x20; // LEN
        memcpy(&asn1Sig[4], &sig[0], 0x20);
        asn1Sig[36] = 0x02; // INT
        asn1Sig[37] = 0x20; // LEN
        memcpy(&asn1Sig[38], &sig[32], 0x20);

        *asn1SigLen = 70;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Verify leaf cert hash's signature.
 *
 *                ECDSA-Verify_sk(SHA256(0x01 || (host ephem pub key) || (se ephem pub key) || AES-CMAK_k_tr(leaf cert hash)))
 *
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         host_init             Host is initiator or responder.
 * @param         certHashBuf           Cert hash buffer.
 * @param         certHashBufLen        Cert hash buffer length.
 * @param         certHashSigBuf        Cert hash's signature buffer.
 * @param         certHashBufSigLen     Cert hash's signature buffer length.
 * @param         initEphemPubkey       Initiator ephemeral public key.
 * @param         respEphemPubkey       Responder ephemeral public key.
 * @param         pubkeyLen              Public key length.
 *
 * @return        Status of searching.
 */
static sss_status_t nx_verify_leaf_cert_hash_signature(nx_auth_sigma_ctx_t *pAuthCtx,
    bool host_init,
    uint8_t *certHashBuf,
    size_t certHashBufLen,
    uint8_t *certHashSigBuf,
    size_t certHashBufSigLen,
    uint8_t *initEphemPubkey,
    uint8_t *respEphemPubkey,
    size_t pubkeyLen)
{
    sss_status_t status                         = kStatus_SSS_Fail;
    sss_mac_t macCtx                            = {0};
    sss_session_t *pSession                     = NULL;
    sss_object_t *pKey                          = NULL;
    uint8_t dataBuf[256]                        = {0};
    size_t leafCertHashCMacLen                  = 0;
    sss_digest_t md                             = {0};
    uint8_t digest[NX_SHA256_BYTE_LEN]          = {0};
    size_t digestLen                            = sizeof(digest);
    sss_asymmetric_t asym                       = {0};
    uint8_t asn1Sig[NX_SIGNATURE_ASN1_BYTE_LEN] = {0}; // Signature in ASN.1 encoded
    size_t asn1SigLen                           = sizeof(asn1Sig);
    size_t asn1ECHdrLen                         = 0;
    uint8_t cmacData[1 + NX_SHA256_BYTE_LEN]    = {0}; // 1 Byte tag + hash

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(certHashBuf != NULL);
    ENSURE_OR_GO_EXIT(initEphemPubkey != NULL);
    ENSURE_OR_GO_EXIT(respEphemPubkey != NULL);

    if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_BRAINPOOL) {
        asn1ECHdrLen = ASN_ECC_BP_256_HEADER_LEN;
    }
    else if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_NIST_P) {
        asn1ECHdrLen = ASN_ECC_NIST_256_HEADER_LEN;
    }
    else {
        goto exit;
    }

    ENSURE_OR_GO_EXIT(pubkeyLen == asn1ECHdrLen + 65);

    // Data to be digest and sign.
    // (0x01 || initiator key sizes supported byte || responder key size selected byte
    // || (host ephem pub key) || (se ephem pub key) || AES-CMAK_k_m1(0x01||leaf cert hash)
    if (host_init == true) {
        dataBuf[SIGMA_I_SIG_DATA_OFFSET_PREFIX] = SIGMA_I_SIG_DATA_PREFIX_01;

        status = tunnel_type_to_keySize(
            pAuthCtx->static_ctx.supportedSecureTunnelType, &dataBuf[SIGMA_I_SIG_DATA_OFFSET_INITIATOR_KEYSIZE]);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        if ((pAuthCtx->dyn_ctx.seKeySize) > UINT8_MAX) {
            LOG_E("seKeySize is incorrect");
            status = kStatus_SSS_Fail;
            goto exit;
        }
        dataBuf[SIGMA_I_SIG_DATA_OFFSET_RESPONDER_KEYSIZE] = pAuthCtx->dyn_ctx.seKeySize;
    }
    else {
        dataBuf[SIGMA_I_SIG_DATA_OFFSET_PREFIX] = SIGMA_I_SIG_DATA_PREFIX_02;

        if ((pAuthCtx->dyn_ctx.seKeySize) > UINT8_MAX) {
            LOG_E("seKeySize is incorrect");
            status = kStatus_SSS_Fail;
            goto exit;
        }
        dataBuf[SIGMA_I_SIG_DATA_OFFSET_INITIATOR_KEYSIZE] = pAuthCtx->dyn_ctx.seKeySize;
        if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES128_NTAG) {
            dataBuf[SIGMA_I_SIG_DATA_OFFSET_RESPONDER_KEYSIZE] = NX_SESSION_KEY_SIZE_BIT_AES128;
        }
        else if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG) {
            dataBuf[SIGMA_I_SIG_DATA_OFFSET_RESPONDER_KEYSIZE] = NX_SESSION_KEY_SIZE_BIT_AES256;
        }
        else {
            LOG_E("Unsupported secure tunnel type");
            goto exit;
        }
    }

    memcpy(&dataBuf[SIGMA_I_SIG_DATA_OFFSET_HOST_EPHEM_PK],
        &initEphemPubkey[asn1ECHdrLen + 1],
        BP256_NISTP256_RAW_PK_SIZE);
    memcpy(
        &dataBuf[SIGMA_I_SIG_DATA_OFFSET_SE_EPHEM_PK], &respEphemPubkey[asn1ECHdrLen + 1], BP256_NISTP256_RAW_PK_SIZE);

    pSession = pAuthCtx->dyn_ctx.k_m1.keyStore->session;
    pKey     = &pAuthCtx->dyn_ctx.k_m1;

    // AES-CMAK_k_m1('01' || leaf_cert hash)
    status = sss_host_mac_context_init(&macCtx, pSession, pKey, kAlgorithm_SSS_CMAC_AES, kMode_SSS_Mac);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    if (host_init == true) {
        cmacData[SIGMA_I_SIG_CMAC_DATA_OFFSET_PREFIX] = SIGMA_I_SIG_DATA_PREFIX_01;
    }
    else {
        cmacData[SIGMA_I_SIG_CMAC_DATA_OFFSET_PREFIX] = SIGMA_I_SIG_DATA_PREFIX_02;
    }
    ENSURE_OR_GO_EXIT(certHashBufLen == NX_SHA256_BYTE_LEN);
    memcpy(&cmacData[SIGMA_I_SIG_CMAC_DATA_OFFSET_HASH], certHashBuf, certHashBufLen);

    leafCertHashCMacLen = sizeof(dataBuf) - SIGMA_I_SIG_DATA_OFFSET_CMAC;
    status              = sss_host_mac_one_go(
        &macCtx, cmacData, sizeof(cmacData), &dataBuf[SIGMA_I_SIG_DATA_OFFSET_CMAC], &leafCertHashCMacLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Sha256(Data)
    status = sss_host_digest_context_init(&md, pSession, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    ENSURE_OR_GO_EXIT((UINT_MAX - SIGMA_I_SIG_DATA_OFFSET_CMAC) >= leafCertHashCMacLen);

    status = sss_host_digest_one_go(
        &md, (const uint8_t *)dataBuf, SIGMA_I_SIG_DATA_OFFSET_CMAC + leafCertHashCMacLen, digest, &digestLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Signature verify sha256(Data)
    status = nx_asn1_encode_signature(certHashSigBuf, certHashBufSigLen, asn1Sig, &asn1SigLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_asymmetric_context_init(
        &asym, pSession, &pAuthCtx->static_ctx.seLeafCertPubKey, kAlgorithm_SSS_SHA256, kMode_SSS_Verify);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_asymmetric_verify_digest(&asym, digest, digestLen, &asn1Sig[0], asn1SigLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_D("Verify received ECC signature passed.");

exit:
    if (macCtx.session != NULL) {
        // Free MAC context
        sss_host_mac_context_free(&macCtx);
    }
    if (md.session != NULL) {
        sss_host_digest_context_free(&md);
    }
    if (asym.session != NULL) {
        sss_host_asymmetric_context_free(&asym);
    }
    return status;
}

#ifdef EX_SSS_SIGMA_I_CACHE_FILE_DIR
/**
 * @brief         Insert leaf cert into cache.
 *
 *                Found an empty slot and insert hash-signature-public key
 *
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         pCertHashBuf          Cert Hash.
 * @param         certHashBufLen        Cert Hash length.
 *
 * @return        Status of insert.
 */
static sss_status_t nx_leaf_cert_cache_insert(void *authCtx, uint8_t *pCertHashBuf, size_t certHashBufLen)
{
    sss_status_t status                          = kStatus_SSS_Fail;
    nx_auth_sigma_ctx_t *pAuthCtx                = (nx_auth_sigma_ctx_t *)authCtx;
    size_t pbKeyBitLen                           = 256;
    uint8_t publicKey[NX_PUBLIC_KEY_BUFFER_SIZE] = {0};
    size_t publicKeyLen                          = sizeof(publicKey);

    ENSURE_OR_GO_EXIT(authCtx != NULL);
    ENSURE_OR_GO_EXIT(pCertHashBuf != NULL);
    ENSURE_OR_GO_EXIT(certHashBufLen == NX_SHA256_BYTE_LEN);

    // Get public key
    publicKeyLen = sizeof(publicKey);
    status       = sss_host_key_store_get_key(pAuthCtx->static_ctx.seLeafCertPubKey.keyStore,
        &(pAuthCtx->static_ctx.seLeafCertPubKey),
        publicKey,
        &publicKeyLen,
        &pbKeyBitLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // ex_insert_hash_pk_to_cache()
    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_insert_hash_pk_to_cache != NULL);
    status = pAuthCtx->static_ctx.fp_insert_hash_pk_to_cache(pCertHashBuf, certHashBufLen, publicKey, publicKeyLen);

exit:
    return status;
}
#endif

/**
 * @brief         Decode ASN.1 Signature. (ASN.1 -> compact signature)
 *
 *                30 44
 *                   02 20 [r]
 *                   02 20 [s]
 *                30 45
 *                   02 21 00 [r]
 *                   02 20 [s]
 *                30 45
 *                   02 20 [r]
 *                   02 21 00 [s]
 *                30 46
 *                   02 21 00 [r]
 *                   02 21 00 [s]
 *                Return r and s.
 *
 * @param         asn1Sig          Signature in ASN.1 encoded.
 * @param         asn1SigLen       Signature length.
 * @param[out]    sigBuf           Signature buffer includes r and s.
 * @param[out]    sigBufLen        Signature buffer length.
 *
 * @return        Status of decode.
 */
static sss_status_t nx_decode_ASN1_signature(uint8_t *asn1Sig, size_t asn1SigLen, uint8_t *sigBuf, size_t *sigBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t *p = NULL, *end = NULL, *pSigBuf = NULL;
    size_t len = 0;
    int ret    = -1;

    ENSURE_OR_GO_EXIT(asn1Sig != NULL);
    ENSURE_OR_GO_EXIT(sigBuf != NULL);
    ENSURE_OR_GO_EXIT(sigBufLen != NULL);
    ENSURE_OR_GO_EXIT(*sigBufLen >= 2 * NX_EC_PRIVATE_KEY_BYTE_LEN);

    p       = asn1Sig;
    len     = asn1SigLen;
    end     = p + asn1SigLen;
    pSigBuf = sigBuf;

    // SEQ
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
        LOG_E("Signature SEQ error");
        goto exit;
    }

    // INTEGER
    ret = -1;
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_INTEGER)) != 0) {
        LOG_E("Signature r error");
        goto exit;
    }

    memset(sigBuf, 0, *sigBufLen);

    if (len == 0x21) {
        // p -> 00 [r]
        ENSURE_OR_GO_EXIT(len == 33);
        memcpy(pSigBuf, p + 1, len - 1);
        *sigBufLen = len - 1;
        pSigBuf += len - 1; // Target ptr
    }
    else {
        ENSURE_OR_GO_EXIT(len <= NX_EC_PRIVATE_KEY_BYTE_LEN);
        memcpy(pSigBuf + (NX_EC_PRIVATE_KEY_BYTE_LEN - len), p, len);
        *sigBufLen = NX_EC_PRIVATE_KEY_BYTE_LEN;
        pSigBuf += NX_EC_PRIVATE_KEY_BYTE_LEN; // Target ptr
    }

    p += len;
    // INTEGER
    ret = -1;
    if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_INTEGER)) != 0) {
        LOG_E("Signature s error");
        goto exit;
    }

    if (len == 0x21) {
        // p -> 00 [s]
        ENSURE_OR_GO_EXIT(len == 33);
        memcpy(pSigBuf, p + 1, len - 1);
        *sigBufLen += len - 1;
    }
    else {
        ENSURE_OR_GO_EXIT(len <= NX_EC_PRIVATE_KEY_BYTE_LEN);
        memcpy(pSigBuf + (NX_EC_PRIVATE_KEY_BYTE_LEN - len), p, len);
        *sigBufLen += NX_EC_PRIVATE_KEY_BYTE_LEN;
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Construct cert hash and signature C-APDU.
 *                Tx C-APDU.
 *
 *                C_k_i = AES_CCM_Enc_k_Ei(leaf_cert_hash || Init_ECC_Sig)
 *
 * @param         seSession          SE session
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         hostEphemPubkey       Host ephem public key.
 * @param         seEphemPubkey         SE ephem public key.
 * @param         pubkeyLen             Public key length.
 * @param[out]    rxEncCertReqBuf       Received encrpyted cert request.
 * @param         pRxEncCertReqBufLen   Received encrpyted cert request length.
 *
 * @return        Status.
 */
static sss_status_t nx_verifier_Tx_cert_hash_sig(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *hostEphemPubkey,
    uint8_t *seEphemPubkey,
    size_t pubkeyLen,
    uint8_t *rxTag,
    uint8_t *rxEncCertReqBuf,
    size_t *pRxEncCertReqBufLen)
{
    sss_status_t status                                                 = kStatus_SSS_Fail;
    uint8_t ckiData[NX_SHA256_BYTE_LEN + NX_ECDSA_P256_SIG_BUFFER_SIZE] = {0};
    size_t ckiDataLen                                                   = sizeof(ckiData);
    uint8_t *pNonce                                                     = NULL;
    size_t nonceLen                                                     = 0;
    sss_object_t *pCCMKey                                               = NULL;
    uint8_t cmdPayload[NX_SHA256_BYTE_LEN + 2 * NX_EC_PRIVATE_KEY_BYTE_LEN + NX_AES256_CCM_TAG_LENGH] = {0};
    uint8_t *encbuf                                                                                   = &cmdPayload[0];
    size_t encbufLen                    = NX_SHA256_BYTE_LEN + 2 * NX_EC_PRIVATE_KEY_BYTE_LEN; // sha256+2*keylen
    uint8_t *tagBuf                     = &cmdPayload[NX_SHA256_BYTE_LEN + 2 * NX_EC_PRIVATE_KEY_BYTE_LEN];
    size_t tagLen                       = NX_AES256_CCM_TAG_LENGH;
    uint8_t cmdBuf[106]                 = {0};
    uint8_t *pCmdBuf                    = NULL;
    size_t cmdBufLen                    = 0;
    int tlvRet                          = 1;
    tlvHeader_t hdr                     = {{CLA_ISO7816, INS_GP_ISO_GENERAL_AUTHENTICATE, P1_SIGMA_I, 0}};
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                    = &rspbuf[0];
    size_t rspbufLen                    = sizeof(rspbuf);
    smStatus_t retStatus                = SM_NOT_OK;
    size_t asn1ECHdrLen                 = 0;

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(hostEphemPubkey != NULL);
    ENSURE_OR_GO_EXIT(seEphemPubkey != NULL);

    if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_BRAINPOOL) {
        asn1ECHdrLen = ASN_ECC_BP_256_HEADER_LEN;
    }
    else if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_NIST_P) {
        asn1ECHdrLen = ASN_ECC_NIST_256_HEADER_LEN;
    }
    else {
        goto exit;
    }

    hdr.hdr[3] = pAuthCtx->static_ctx.seCertRepoId; // P2 is cert repo id.

    ENSURE_OR_GO_EXIT(pubkeyLen == asn1ECHdrLen + 65);

    // C_k_i Data = host_leaf_cert_hash || Init_ECC_Sig
    status = nx_prepare_host_c_k_data(pAuthCtx, true, hostEphemPubkey, seEphemPubkey, pubkeyLen, ckiData, &ckiDataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D("Tx host leaf cert hash", ckiData, NX_SHA256_BYTE_LEN);
    LOG_MAU8_D("Tx host ECC signature", &(ckiData[NX_SHA256_BYTE_LEN]), ckiDataLen - NX_SHA256_BYTE_LEN);
    // C_k_i = AES_CCM_Enc_k_e1(Data)
    pNonce   = pAuthCtx->dyn_ctx.iv_e1;
    nonceLen = sizeof(pAuthCtx->dyn_ctx.iv_e1);
    pCCMKey  = &pAuthCtx->dyn_ctx.k_e1;

    status    = kStatus_SSS_Fail;
    encbufLen = ckiDataLen; // sha256+2*keylen
    ENSURE_OR_GO_EXIT(sizeof(cmdPayload) > encbufLen);
    tagBuf = &cmdPayload[encbufLen];
    status = nx_enc_AES256_CCM(pCCMKey, pNonce, nonceLen, ckiData, ckiDataLen, encbuf, &encbufLen, tagBuf, &tagLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // pAuthCtx->dyn_ctx.iv_s/iv_e1++;
    increase_big_data(pNonce, nonceLen);

    // Send cert hash and signature C-APDU
    pCmdBuf = &cmdBuf[0];
    // encrpyted message: A1 xx <message payload>
    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT((UINT_MAX - encbufLen) >= tagLen);
    tlvRet = TLVSET_u8buf("Host hash and sig",
        &pCmdBuf,
        &cmdBufLen,
        NX_TAG_MSGI_HASH_AND_SIG,
        &cmdPayload[0],
        encbufLen + tagLen,
        sizeof(cmdBuf));
    ENSURE_OR_GO_EXIT(0 == tlvRet)

    retStatus = DoAPDUTxRx_s_Case4(seSession, &hdr, cmdBuf, cmdBufLen, NULL, 0, rspbuf, &rspbufLen, NULL);

    if (retStatus == SM_OK) {
        // Get SE encrypted certificate
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        *rxTag          = rspbuf[0];
        ENSURE_OR_GO_EXIT((rspbuf[0] == NX_TAG_MSG_SESSION_OK) || (rspbuf[0] == NX_TAG_MSGR_CERT_REQUEST));

        if (rspbuf[0] == NX_TAG_MSGR_CERT_REQUEST) {
            ENSURE_OR_GO_EXIT(rspbufLen >= 4);
            // Cert request should always be B2 0C 87 0A
            ENSURE_OR_GO_EXIT((rspbuf[1] == 0x0C) && (rspbuf[2] == NX_TAG_ENCRYPTED_PAYLOAD) && (rspbuf[3] == 0x0A));
            rspIndex = 2;
        }

        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, rspbuf[rspIndex], rxEncCertReqBuf, pRxEncCertReqBufLen);
        ENSURE_OR_GO_EXIT(0 == tlvRet)

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }
    }

    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Desrypt SE cert request.
 *
 *                This API decrpyt SE cert request.
 *
 * @param         pAuthCtx          Context Pointer to auth context.
 * @param         encCertBuf        Encrypted cert request.
 * @param         encCertBufLen     Encrypted cert request length.
 * @param         host_init         Host is initiator or responder.
 * @param[out]    seCertReqBuf      Cert request.
 * @param[out]    seCertReqBufLen   Cert request length.
 *
 * @return        Status of calculate session keys and NONCE.
 */
static sss_status_t nx_decrypt_se_cert_req(nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *encCertBuf,
    size_t encCertBufLen,
    bool host_init,
    uint8_t *seCertReqBuf,
    size_t *seCertReqBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    sss_object_t *pKey  = NULL;
    uint8_t *pNonce     = NULL;
    size_t nonceLen     = 0;
    size_t encBufLen    = 0;
    uint8_t *tagBuf     = NULL;
    size_t tagLen       = NX_AES256_CCM_TAG_LENGH;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(encCertBuf != NULL);
    ENSURE_OR_GO_EXIT(encCertBufLen > NX_AES256_CCM_TAG_LENGH);
    ENSURE_OR_GO_EXIT(seCertReqBuf != NULL);
    ENSURE_OR_GO_EXIT(*seCertReqBufLen >= 2); // SE Cert Req is 2 bytes.
    encBufLen = encCertBufLen - NX_AES256_CCM_TAG_LENGH;
    tagBuf    = &encCertBuf[encCertBufLen - NX_AES256_CCM_TAG_LENGH];

    pKey     = &pAuthCtx->dyn_ctx.k_e1;
    pNonce   = pAuthCtx->dyn_ctx.iv_e1;
    nonceLen = sizeof(pAuthCtx->dyn_ctx.iv_e1);

    // AES CCM on "cert request"
    status =
        nx_dec_AES256_CCM(pKey, pNonce, nonceLen, encCertBuf, encBufLen, tagBuf, tagLen, seCertReqBuf, seCertReqBufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    increase_big_data(pNonce, nonceLen);

exit:
    return status;
}

static sss_status_t nx_default_host_cert(sss_cipher_type_t curveType, int level, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((curveType == kSSS_CipherType_EC_BRAINPOOL) || (curveType == kSSS_CipherType_EC_NIST_P));

    if (level == NX_CERTIFICATE_LEVEL_LEAF) {
        if (curveType == kSSS_CipherType_EC_BRAINPOOL) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_CERT
            uint8_t hostLeafCertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostLeafCertBP256));
            memcpy(buffer, hostLeafCertBP256, sizeof(hostLeafCertBP256));
            *bufferLen = sizeof(hostLeafCertBP256);
#else
            LOG_E("EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_CERT not defined");
            goto exit;
#endif
        }
        else {
#ifdef EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_CERT
            uint8_t hostLeafCertNistp256[] = EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostLeafCertNistp256));
            memcpy(buffer, hostLeafCertNistp256, sizeof(hostLeafCertNistp256));
            *bufferLen = sizeof(hostLeafCertNistp256);
#else
            LOG_E("EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_CERT not defined");
            goto exit;
#endif
        }
    }
    else if (level == NX_CERTIFICATE_LEVEL_P1) {
        if (curveType == kSSS_CipherType_EC_BRAINPOOL) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_HOST_P1_CERT
            uint8_t hostP1CertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_HOST_P1_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostP1CertBP256));
            memcpy(buffer, hostP1CertBP256, sizeof(hostP1CertBP256));
            *bufferLen = sizeof(hostP1CertBP256);
#else
            LOG_E("EX_SSS_SIGMA_I_BRAINPOOL256_HOST_P1_CERT not defined");
            goto exit;
#endif
        }
        else {
#ifdef EX_SSS_SIGMA_I_NISTP256_HOST_P1_CERT
            uint8_t hostP1CertNistp256[] = EX_SSS_SIGMA_I_NISTP256_HOST_P1_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostP1CertNistp256));
            memcpy(buffer, hostP1CertNistp256, sizeof(hostP1CertNistp256));
            *bufferLen = sizeof(hostP1CertNistp256);
#else
            LOG_E("EX_SSS_SIGMA_I_NISTP256_HOST_P1_CERT not defined");
            goto exit;
#endif
        }
    }
    else if (level == NX_CERTIFICATE_LEVEL_P2) {
        if (curveType == kSSS_CipherType_EC_BRAINPOOL) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_HOST_P2_CERT
            uint8_t hostP2CertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_HOST_P2_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostP2CertBP256));
            memcpy(buffer, hostP2CertBP256, sizeof(hostP2CertBP256));
            *bufferLen = sizeof(hostP2CertBP256);
#else
            LOG_E("EX_SSS_SIGMA_I_BRAINPOOL256_HOST_P2_CERT not defined");
            goto exit;
#endif
        }
        else {
#ifdef EX_SSS_SIGMA_I_NISTP256_HOST_P2_CERT
            uint8_t hostP2CertNistp256[] = EX_SSS_SIGMA_I_NISTP256_HOST_P2_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostP2CertNistp256));
            memcpy(buffer, hostP2CertNistp256, sizeof(hostP2CertNistp256));
            *bufferLen = sizeof(hostP2CertNistp256);
#else
            LOG_E("EX_SSS_SIGMA_I_NISTP256_HOST_P2_CERT not defined");
            goto exit;
#endif
        }
    }
    else {
        LOG_E("Invalid cert level");
    }

    status = kStatus_SSS_Success;
exit:
    return status;
}

static sss_status_t nx_default_se_root_cert(sss_cipher_type_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((curveType == kSSS_CipherType_EC_BRAINPOOL) || (curveType == kSSS_CipherType_EC_NIST_P));

    if (curveType == kSSS_CipherType_EC_BRAINPOOL) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_ROOT_CERT
        uint8_t seRootCertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_ROOT_CERT;
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seRootCertBP256));
        memcpy(buffer, seRootCertBP256, sizeof(seRootCertBP256));
        *bufferLen = sizeof(seRootCertBP256);
#else
        LOG_E("EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_ROOT_CERT not defined");
        goto exit;
#endif
    }
    else {
#ifdef EX_SSS_SIGMA_I_NISTP256_DEVICE_ROOT_CERT
        uint8_t seRootCertNistp256[] = EX_SSS_SIGMA_I_NISTP256_DEVICE_ROOT_CERT;
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seRootCertNistp256));
        memcpy(buffer, seRootCertNistp256, sizeof(seRootCertNistp256));
        *bufferLen = sizeof(seRootCertNistp256);
#else
        LOG_E("EX_SSS_SIGMA_I_NISTP256_DEVICE_ROOT_CERT not defined");
        goto exit;
#endif
    }

#if defined(EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_ROOT_CERT) || defined(EX_SSS_SIGMA_I_NISTP256_DEVICE_ROOT_CERT)
    status = kStatus_SSS_Success;
#endif

exit:
    return status;
}

static sss_status_t nx_get_se_root_cert(sss_cipher_type_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t maxBuffLen   = 0;

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
    char *fileName                                                             = EX_DEVICE_ROOT_CERT;
    char *cert_key_path_env                                                    = NULL;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};

#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cert_key_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cert_key_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;

    if (cert_key_path_env != NULL) {
        // Get file from Path indicated by ENV
        LOG_D("Using certificate/key from:'%s' (ENV=%s)", cert_key_path_env, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = get_full_path_file_name(cert_key_path_env, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = kStatus_SSS_Fail;
        status = read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
#if defined(_MSC_VER)
        if (cert_key_path_env) {
            free(cert_key_path_env);
        }
#endif //_MSC_VER
    }
    else if (nx_dir_exists(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR) == true) {
        LOG_D(
            "Using certificate/key from:'%s' (Default path). "
            "You can specify certificates/keys file using ENV=%s",
            EX_SSS_SIGMA_I_CERT_INCLUDE_DIR,
            EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = get_full_path_file_name(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = kStatus_SSS_Fail;
        status = read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
    }
    else {
        // Get default value.
        LOG_I("Using root certificate from lib/sss/inc/fsl_sss_nx_auth_keys.h");
        status = nx_default_se_root_cert(curveType, buffer, &maxBuffLen);
    }
#else

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;

    // Get default value.
    LOG_I("Using root certificate from lib/sss/inc/fsl_sss_nx_auth_keys.h");
    status = nx_default_se_root_cert(curveType, buffer, &maxBuffLen);
#endif

    *bufferLen = maxBuffLen;
exit:
    return status;
}

static sss_status_t nx_get_host_cert(
    NX_CERTIFICATE_LEVEL_t level, sss_cipher_type_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t maxBuffLen   = 0;

#ifdef EX_SSS_SIGMA_I_CERT_INCLUDE_DIR
    char *leafCertName                                                         = EX_HOST_LEAF_CERT;
    char *p1CertName                                                           = EX_HOST_P1_CERT;
    char *p2CertName                                                           = EX_HOST_P2_CERT;
    char *fileName                                                             = NULL;
    char *cert_key_path_env                                                    = NULL;
    char fullPathFileName[EX_MAX_INCLUDE_DIR_LENGTH + EX_MAX_EXTRA_DIR_LENGTH] = {0};

#if defined(_MSC_VER)
    size_t sz = 0;
    _dupenv_s(&cert_key_path_env, &sz, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#else
    cert_key_path_env = getenv(EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);
#endif //_MSC_VER

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((level == NX_CERTIFICATE_LEVEL_LEAF) || (level == NX_CERTIFICATE_LEVEL_P1) ||
                      (level == NX_CERTIFICATE_LEVEL_P2));

    maxBuffLen = *bufferLen;

    if (level == NX_CERTIFICATE_LEVEL_LEAF) {
        fileName = leafCertName;
    }
    else if (level == NX_CERTIFICATE_LEVEL_P1) {
        fileName = p1CertName;
    }
    else {
        fileName = p2CertName;
    }

    if (cert_key_path_env != NULL) {
        // Get file from Path indicated by ENV
        LOG_D("Using certificate/key from:'%s' (ENV=%s)", cert_key_path_env, EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = get_full_path_file_name(cert_key_path_env, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
#if defined(_MSC_VER)
        if (cert_key_path_env) {
            free(cert_key_path_env);
        }
#endif //_MSC_VER
    }
    else if (nx_dir_exists(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR) == true) {
        LOG_D(
            "Using certificate/key from:'%s' (Default path). "
            "You can specify certificates/keys file using ENV=%s",
            EX_SSS_SIGMA_I_CERT_INCLUDE_DIR,
            EX_SSS_SIGMA_I_CERT_PATH_ENV_VAR);

        status = get_full_path_file_name(EX_SSS_SIGMA_I_CERT_INCLUDE_DIR, fileName, curveType, fullPathFileName);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = read_file_from_fs(fullPathFileName, buffer, &maxBuffLen);
    }
    else {
        // Get default value.
        LOG_D("Using default SE certificates");
        status = nx_default_host_cert(curveType, level, buffer, &maxBuffLen);
    }
#else

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);

    maxBuffLen = *bufferLen;

    // Get default value.
    LOG_D("Using default SE certificates");
    status = nx_default_host_cert(curveType, level, buffer, &maxBuffLen);
#endif

    *bufferLen = maxBuffLen;
exit:
    return status;
}

/**
 * @brief         Construct host cert replay C-APDU.
 *                Tx C-APDU.
 *
 *                A3 82 xx xx <encrpted certificate>
 *                AES_CCM_Enc_k_ci (7F 21/22 <cert/com-cert>)
 *
 * @param         seSession          SE session
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         rxSeCertReq           Received SE cert request.
 * @param         rxSeCertReqLen        Received SE cert request length.
 * @param[out]    rxTag                 Next received tag.
 * @param[out]    rxEncCertReqBuf       Next received encrpyted cert request.
 * @param[out]    pRxEncCertReqBufLen   Next received encrpyted cert request length.
 *
 * @return        Status.
 */
static sss_status_t nx_Tx_cert_reply_sig(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *rxSeCertReq,
    size_t rxSeCertReqLen,
    bool host_init,
    uint8_t *rxTag,
    uint8_t *rxEncCertReqBuf,
    size_t *pRxEncCertReqBufLen)
{
    sss_status_t status                     = kStatus_SSS_Fail;
    uint8_t *pNonce                         = NULL;
    size_t nonceLen                         = 0;
    sss_object_t *pKey                      = NULL;
    uint8_t *pEncbuf                        = NULL; // reuse command buffer.
    size_t encbufLen                        = 0;
    uint8_t tagBuf[NX_AES256_CCM_TAG_LENGH] = {0};
    size_t tagLen                           = NX_AES256_CCM_TAG_LENGH;
    uint8_t *pBuf;
    size_t bufLen = 0, certReplyLen = 0;
    uint8_t certBuf[NX_MAX_CERT_BUFFER_SIZE]       = {0};
    uint8_t *pCertBuf                              = (uint8_t *)&certBuf;
    size_t certBufLen                              = NX_MAX_CERT_BUFFER_SIZE;
    int tlvRet                                     = 0;
    tlvHeader_t hdr                                = {{CLA_ISO7816, INS_GP_ISO_GENERAL_AUTHENTICATE, P1_SIGMA_I, 0}};
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]            = {0};
    uint8_t *pRspbuf                               = &rspbuf[0];
    size_t rspbufLen                               = sizeof(rspbuf);
    smStatus_t retStatus                           = SM_NOT_OK;
    uint8_t taggedCertBuf[NX_MAX_CERT_BUFFER_SIZE] = {0};
    uint8_t *taggedCert                            = (uint8_t *)&taggedCertBuf;
    size_t taggedCertLen                           = NX_MAX_CERT_BUFFER_SIZE;
    uint8_t tagCertReply;
    uint8_t cmdBuf[NX_MAX_CERT_BUFFER_SIZE] = {0};
    size_t cmdBufLen                        = NX_MAX_CERT_BUFFER_SIZE;

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(rxSeCertReq != NULL);
    ENSURE_OR_GO_EXIT(rxEncCertReqBuf != NULL);
    ENSURE_OR_GO_EXIT(pRxEncCertReqBufLen != NULL);
    ENSURE_OR_GO_EXIT(rxSeCertReqLen == 2); // Cert request can only be 2 bytes.

    hdr.hdr[3] = pAuthCtx->static_ctx.seCertRepoId; // P2 is cert repo id.

    if (((nx_cert_req_tag_t)rxSeCertReq[0] == NX_CERT_REQ_TAG_LEAF) && (rxSeCertReq[1] == 0X00)) {
        // Leaf cert request
        LOG_D("Tx Leaf cert reply");

        // Get Leaf Cert
        status =
            nx_get_host_cert(NX_CERTIFICATE_LEVEL_LEAF, pAuthCtx->static_ctx.hostCertCurveType, pCertBuf, &certBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }
    else if (((nx_cert_req_tag_t)rxSeCertReq[0] == NX_CERT_REQ_TAG_P1) && (rxSeCertReq[1] == 0X00)) {
        // P1 cert request
        LOG_D("Tx P1 cert reply");

        // Get P1 Cert
        status =
            nx_get_host_cert(NX_CERTIFICATE_LEVEL_P1, pAuthCtx->static_ctx.hostCertCurveType, pCertBuf, &certBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }
    else if (((nx_cert_req_tag_t)rxSeCertReq[0] == NX_CERT_REQ_TAG_P2) && (rxSeCertReq[1] == 0X00)) {
        // P2 cert request
        LOG_D("Tx P2 cert reply");

        // Get P2 Cert
        status =
            nx_get_host_cert(NX_CERTIFICATE_LEVEL_P2, pAuthCtx->static_ctx.hostCertCurveType, pCertBuf, &certBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    }
    else {
        // error
        LOG_E("Unknow cert request 0x%x 0x0x", rxSeCertReq[0], rxSeCertReq[1]);
        goto exit;
    }

    // Generate Tagged Certificate
    //    7F 21 <cert>                      - uncompressed cert
    pBuf   = &taggedCert[1];
    bufLen = 0;
    // uncompressed cert: 21 xx <cert>
    tlvRet = TLVSET_u8buf(
        "cert", &pBuf, &bufLen, NX_TAG_UNCOMPRESSED_CERT, pCertBuf, certBufLen, NX_MAX_CERT_BUFFER_SIZE - 1);
    if (0 != tlvRet) {
        goto exit;
    }
    taggedCert[0] = 0x7F;
    ENSURE_OR_GO_EXIT((UINT_MAX - 1) >= bufLen);
    taggedCertLen = bufLen + 1;

    // Generate Encrypted Tagged Certificate
    // AES_CCM_Enc_k_ci(tagged cert)
    // AES_CCM_Enc_k_cr(Responder)

    pNonce   = pAuthCtx->dyn_ctx.iv_e1;
    nonceLen = sizeof(pAuthCtx->dyn_ctx.iv_e1);
    pKey     = &pAuthCtx->dyn_ctx.k_e1;
    if (host_init == true) {
        tagCertReply = NX_TAG_MSGI_CERT_REPLY;
    }
    else {
        tagCertReply = NX_TAG_MSGR_CERT_REPLY;
    }

    status = kStatus_SSS_Fail; // Reinitializing exit status

    // enc buffer reuse cmdBuf and reserve 10 bytes for Tag and length.
    pEncbuf   = &cmdBuf[10];
    encbufLen = cmdBufLen - 10;
    status = nx_enc_AES256_CCM(pKey, pNonce, nonceLen, taggedCert, taggedCertLen, pEncbuf, &encbufLen, tagBuf, &tagLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Append tag to enc
    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT((UINT_MAX - 10) >= encbufLen);
    ENSURE_OR_GO_EXIT(cmdBufLen > (10 + encbufLen));
    memcpy(&cmdBuf[10 + encbufLen], &tagBuf[0], tagLen);

    // A3 82 xx xx <enc certificate>        - MSGI_CERT_REPLY message
    // B3 82 xx xx <enc certificate>        - MSGR_CERT_REPLY message
    pBuf         = &cmdBuf[0];
    certReplyLen = 0;
    ENSURE_OR_GO_EXIT((UINT_MAX - encbufLen) >= tagLen);
    tlvRet = TLVSET_u8buf(
        "cert reply", &pBuf, &certReplyLen, tagCertReply, pEncbuf, encbufLen + tagLen, NX_MAX_BUF_SIZE_CMD);
    if (0 != tlvRet) {
        goto exit;
    }

    // pAuthCtx->dyn_ctx.iv_ci++;
    increase_big_data(pNonce, nonceLen);

    retStatus = DoAPDUTxRx_s_Case4_ext(seSession, &hdr, cmdBuf, certReplyLen, NULL, 0, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        // Get SE encrypted certificate
        retStatus       = SM_NOT_OK;
        size_t rspIndex = 0;
        *rxTag          = rspbuf[0];
        if (host_init == true) {
            ENSURE_OR_GO_EXIT((rspbuf[0] == NX_TAG_MSG_SESSION_OK) || (rspbuf[0] == NX_TAG_MSGR_CERT_REQUEST));
            if (rspbuf[0] == NX_TAG_MSGR_CERT_REQUEST) {
                ENSURE_OR_GO_EXIT(rspbufLen >= 4);
                // Cert request should always be B2 0C 87 0A
                ENSURE_OR_GO_EXIT(
                    (rspbuf[1] == 0x0C) && (rspbuf[2] == NX_TAG_ENCRYPTED_PAYLOAD) && (rspbuf[3] == 0x0A));
                rspIndex = 2;
            }
        }
        else {
            ENSURE_OR_GO_EXIT((rspbuf[0] == NX_TAG_MSGI_CERT_REQUEST) || (rspbuf[0] == NX_TAG_MSGI_HASH_AND_SIG));
            if (rspbuf[0] == NX_TAG_MSGI_CERT_REQUEST) {
                ENSURE_OR_GO_EXIT(rspbufLen >= 4);
                // Cert request should always be A2 0C 87 0A
                ENSURE_OR_GO_EXIT(
                    (rspbuf[1] == 0x0C) && (rspbuf[2] == NX_TAG_ENCRYPTED_PAYLOAD) && (rspbuf[3] == 0x0A));
                rspIndex = 2;
            }
        }

        tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, rspbuf[rspIndex], rxEncCertReqBuf, pRxEncCertReqBufLen);
        if (0 != tlvRet) {
            goto exit;
        }

        if ((rspIndex + 2) == rspbufLen) {
            retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
        }

        *rxTag = rspbuf[0];
    }

    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Construct Transfer control C-APDU.
 *                Tx C-APDU.
 *
 *                -> B0 00
 *                <- A0 43
 *                      86 41 04 <public key 64B>
 *
 * @param         seSession      SE session
 * @param         pAuthCtx          Context Pointer to auth context.
 * @param[out]    rxPubKeyBuf       Received SE public key.
 * @param[out]    pRxPubKeyBufLen   Received SE public key length.
 *
 * @return        Status.
 */
static sss_status_t nx_prover_Tx_control_transfer(
    pSeSession_t seSession, nx_auth_sigma_ctx_t *pAuthCtx, uint8_t *rxPubKeyBuf, size_t *pRxPubKeyBufLen)
{
    sss_status_t status                 = kStatus_SSS_Fail;
    uint8_t cmdBuf[1024]                = {0};
    uint8_t *pCmdBuf                    = NULL;
    size_t cmdBufLen                    = 0;
    int tlvRet                          = 1;
    tlvHeader_t hdr                     = {{CLA_ISO7816, INS_GP_ISO_GENERAL_AUTHENTICATE, P1_SIGMA_I, 0}};
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                    = &rspbuf[0];
    size_t rspbufLen                    = sizeof(rspbuf);
    smStatus_t retStatus                = SM_NOT_OK;
    uint8_t *pPubKeyData                = NULL; // Buffer used for public key in R-APDU
    size_t pubKeyDataLen                = 0;
    /* clang-format off */
    uint8_t bp256_header[] = { 0x30, 0x5a, 0x30, 0x14, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
        0x02, 0x01, 0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01,
        0x01, 0x07, 0x03, 0x42, 0x00 };
    uint8_t nistp256_header[] = { \
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, \
        0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, \
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, \
        0x42, 0x00 \
        };
    /* clang-format on */
    size_t asn1HeadLen = 0;
    uint8_t keySize = 0, seKeySize = 0;

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(rxPubKeyBuf != NULL);
    ENSURE_OR_GO_EXIT(pRxPubKeyBufLen != NULL);

    status = tunnel_type_to_keySize(pAuthCtx->static_ctx.supportedSecureTunnelType, &keySize);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status     = kStatus_SSS_Fail;                  // Reinitializing status value
    hdr.hdr[3] = pAuthCtx->static_ctx.seCertRepoId; // P2 is cert repo id.

    // Public key ASN.1 Header
    if (pAuthCtx->static_ctx.ephemKeypair.cipherType == kSSS_CipherType_EC_BRAINPOOL) {
        ENSURE_OR_GO_EXIT(*pRxPubKeyBufLen > sizeof(bp256_header));
        asn1HeadLen = sizeof(bp256_header);
        memcpy(rxPubKeyBuf, bp256_header, sizeof(bp256_header));
        pPubKeyData   = rxPubKeyBuf + sizeof(bp256_header); // Buffer used for public key in R-APDU
        pubKeyDataLen = *pRxPubKeyBufLen - sizeof(bp256_header);
    }
    else if (pAuthCtx->static_ctx.ephemKeypair.cipherType == kSSS_CipherType_EC_NIST_P) {
        ENSURE_OR_GO_EXIT(*pRxPubKeyBufLen > sizeof(nistp256_header));
        asn1HeadLen = sizeof(nistp256_header);
        memcpy(rxPubKeyBuf, nistp256_header, sizeof(nistp256_header));
        pPubKeyData   = rxPubKeyBuf + sizeof(nistp256_header); // Buffer used for public key in R-APDU
        pubKeyDataLen = *pRxPubKeyBufLen - sizeof(nistp256_header);
    }
    else {
        LOG_E("Unsupported curves %u", pAuthCtx->static_ctx.ephemKeypair.cipherType);
        goto exit;
    }

    // B0 00        - MSGR_START_PROTOCOL message
    pCmdBuf   = &cmdBuf[0];
    cmdBufLen = 0;
    tlvRet    = TLVSET_u8buf(
        "control transfer", &pCmdBuf, &cmdBufLen, NX_TAG_MSGR_START_PROTOCOL, &cmdBuf[0], 0, sizeof(cmdBuf));
    if (0 != tlvRet) {
        goto exit;
    }

    retStatus = DoAPDUTxRx_s_Case4(seSession, &hdr, cmdBuf, cmdBufLen, NULL, 0, rspbuf, &rspbufLen, NULL);
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    // Get SE encrypted certificate
    size_t rspIndex = 0;
    tlvRet          = tlvGet_ValueIndex(pRspbuf, &rspIndex, rspbufLen, NX_TAG_MSGI_PUBLIC_KEY);
    if (0 != tlvRet) {
        goto exit;
    }

    tlvRet = tlvGet_U8(pRspbuf, &rspIndex, rspbufLen, NX_TAG_KEY_SIZE, &seKeySize);
    if (0 != tlvRet) {
        goto exit;
    }

    pAuthCtx->dyn_ctx.seKeySize = seKeySize; // Store device supported key size.
    if ((seKeySize & NX_SESSION_KEY_SIZE_BIT_AES256) && (keySize & NX_SESSION_KEY_SIZE_BIT_AES256)) {
        // Both side support AES256
        pAuthCtx->dyn_ctx.selectedSecureTunnelType = knx_SecureSymmType_AES256_NTAG;
        LOG_D("Select secure tunnel type AES256");
    }
    else if ((seKeySize & (NX_SESSION_KEY_SIZE_BIT_AES128 | NX_SESSION_KEY_SIZE_BIT_AES256)) == 0) {
        LOG_E("Unsupported NX secure tunnel type 0x%x", seKeySize);
        goto exit;
    }
    else {
        pAuthCtx->dyn_ctx.selectedSecureTunnelType = knx_SecureSymmType_AES128_NTAG;
        LOG_D("Select secure tunnel type AES128");
    }

    tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, NX_TAG_EPHEM_PUB_KEY, pPubKeyData, &pubKeyDataLen);
    if (0 != tlvRet) {
        goto exit;
    }

    retStatus = SM_NOT_OK;
    if ((rspIndex + 2) == rspbufLen) {
        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
    }
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    // Add ASN.1 header length.
    *pRxPubKeyBufLen = pubKeyDataLen + asn1HeadLen;

    status = kStatus_SSS_Success;
exit:
    return status;
}

/**
 * @brief         Construct host C_k_r or C_k_i data.
 *
 *                C_k_r data = leaf_cert_hash || Resp_ECC_Sig
 *                C_k_i data = leaf_cert_hash || Init_ECC_Sig
 *
 * @param         pAuthCtx                  Context Pointer to auth context.
 * @param         host_init                 Host works as initiator or responder.
 * @param         hostEphostEpemPubkeyBuf   Host ephem public key.
 * @param         seEpemPubkeyBuf           SE ephem public key.
 * @param         pubKeyLen                 Public key length.
 * @param[out]    ckDataBuf                 C_k_r/C_k_i data
 * @param[out]    ckDataBufLen              C_k_r/C_k_i data length.
 *
 * @return        Status.
 */
static sss_status_t nx_prepare_host_c_k_data(nx_auth_sigma_ctx_t *pAuthCtx,
    bool host_init,
    uint8_t *hostEpemPubkeyBuf, // ASN.1 encoded
    uint8_t *seEpemPubkeyBuf,   // ASN.1 encoded
    size_t pubKeyLen,
    uint8_t *ckDataBuf,
    size_t *ckDataBufLen)
{
    sss_status_t status                          = kStatus_SSS_Fail;
    uint8_t *pHostKeyData                        = NULL;
    uint8_t *pSeKeyData                          = NULL;
    sss_digest_t md                              = {0};
    uint8_t *certHash                            = ckDataBuf;
    size_t certHashLen                           = NX_SHA256_BYTE_LEN;
    uint8_t cmacData[NX_SHA256_BYTE_LEN + 1]     = {0};
    uint8_t sigDataBuf[1000]                     = {0}; // 0x01 || xP || yP || AES-CMAC_k_tr(leaf_cert_hash)
    sss_mac_t macCtx                             = {0};
    sss_session_t *pSession                      = NULL;
    sss_object_t *pMacKey                        = NULL;
    size_t leafCertHashCMacLen                   = 0;
    uint8_t sigDataDigest[NX_SHA256_BYTE_LEN]    = {0};
    size_t sigDataDigestLen                      = sizeof(sigDataDigest);
    sss_asymmetric_t asym                        = {0};
    uint8_t asn1Sig[NX_SIGNATURE_ASN1_BYTE_LEN]  = {0};             // Signature in ASN.1 encoded
    size_t asn1SigLen                            = sizeof(asn1Sig); // Signature in ASN.1 encoded
    size_t compactSigLen                         = NX_ECDSA_P256_SIG_BUFFER_SIZE;
    size_t asn1ECHdrLen                          = 0;
    uint8_t prefix                               = 0;
    uint8_t initKeySize                          = 0;
    uint8_t respSelectedKeySize                  = 0;
    uint8_t leafCertBuf[NX_MAX_CERT_BUFFER_SIZE] = {0};
    uint8_t *leafCert                            = (uint8_t *)&leafCertBuf;
    size_t leafCertLen                           = NX_MAX_CERT_BUFFER_SIZE;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(hostEpemPubkeyBuf != NULL);
    ENSURE_OR_GO_EXIT(seEpemPubkeyBuf != NULL);
    ENSURE_OR_GO_EXIT(ckDataBuf != NULL);
    ENSURE_OR_GO_EXIT(ckDataBufLen != NULL);

    if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_BRAINPOOL) {
        asn1ECHdrLen = ASN_ECC_BP_256_HEADER_LEN;
    }
    else if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_NIST_P) {
        asn1ECHdrLen = ASN_ECC_NIST_256_HEADER_LEN;
    }
    else {
        goto exit;
    }

    ENSURE_OR_GO_EXIT(pubKeyLen == asn1ECHdrLen + 65);

    // Host as initiator C_k_r data = leaf_cert_hash || Resp_ECC_Sig
    // Host as responder C_k_i data = leaf_cert_hash || Init_ECC_Sig

    status =
        nx_get_host_cert(NX_CERTIFICATE_LEVEL_LEAF, pAuthCtx->static_ctx.hostCertCurveType, leafCert, &leafCertLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // host leaf_cert_hash
    status = sss_host_digest_context_init(
        &md, pAuthCtx->static_ctx.ephemKeypair.keyStore->session, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_digest_one_go(&md, (const uint8_t *)(leafCert), leafCertLen, certHash, &certHashLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if (md.session != NULL) {
        sss_host_digest_context_free(&md);
    }

    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(certHashLen == NX_SHA256_BYTE_LEN);

    pHostKeyData = hostEpemPubkeyBuf + asn1ECHdrLen + 1; // Remove asn.1 header and 04
    pSeKeyData   = seEpemPubkeyBuf + asn1ECHdrLen + 1;   // Remove asn.1 header and 04
    // Get prefix, initiator key size, responder selected key size.
    if (host_init == true) {
        prefix = SIGMA_I_SIG_DATA_PREFIX_02;
        status = tunnel_type_to_keySize(pAuthCtx->static_ctx.supportedSecureTunnelType, &initKeySize);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = kStatus_SSS_Fail;
        if (pAuthCtx->dyn_ctx.seKeySize > UINT8_MAX) {
            status = kStatus_SSS_Fail;
            goto exit;
        }
        respSelectedKeySize = pAuthCtx->dyn_ctx.seKeySize;
    }
    else {
        prefix = SIGMA_I_SIG_DATA_PREFIX_01;
        if (pAuthCtx->dyn_ctx.seKeySize > UINT8_MAX) {
            status = kStatus_SSS_Fail;
            goto exit;
        }
        initKeySize = pAuthCtx->dyn_ctx.seKeySize;

        if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES128_NTAG) {
            respSelectedKeySize = NX_SESSION_KEY_SIZE_BIT_AES128;
        }
        else if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG) {
            respSelectedKeySize = NX_SESSION_KEY_SIZE_BIT_AES256;
        }
        else {
            LOG_E("Unsupported secure tunnel type");
            goto exit;
        }
    }

    // Data to be digest and sign.
    pSession = pAuthCtx->dyn_ctx.k_m1.keyStore->session;
    pMacKey  = &pAuthCtx->dyn_ctx.k_m1;

    // (prefix || (se supported key size) || (host selected key size) || (se ephem pub key) || (host ephem pub key)
    sigDataBuf[SIGMA_I_SIG_DATA_OFFSET_PREFIX]            = prefix;
    sigDataBuf[SIGMA_I_SIG_DATA_OFFSET_INITIATOR_KEYSIZE] = initKeySize;
    sigDataBuf[SIGMA_I_SIG_DATA_OFFSET_RESPONDER_KEYSIZE] = respSelectedKeySize;
    memcpy(&sigDataBuf[SIGMA_I_SIG_DATA_OFFSET_HOST_EPHEM_PK], pSeKeyData, 64);
    memcpy(&sigDataBuf[SIGMA_I_SIG_DATA_OFFSET_SE_EPHEM_PK], pHostKeyData, 64);

    // AES-CMAK_k_m1(prefix||leaf cert hash) or
    // AES-CMAC_k_tr(host leaf cert hash)
    status = sss_host_mac_context_init(&macCtx, pSession, pMacKey, kAlgorithm_SSS_CMAC_AES, kMode_SSS_Mac);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    cmacData[SIGMA_I_SIG_CMAC_DATA_OFFSET_PREFIX] = prefix;
    memcpy(&cmacData[SIGMA_I_SIG_CMAC_DATA_OFFSET_HASH], certHash, certHashLen);
    leafCertHashCMacLen = sizeof(sigDataBuf) - SIGMA_I_SIG_DATA_OFFSET_CMAC;

    status = sss_host_mac_one_go(
        &macCtx, cmacData, sizeof(cmacData), &sigDataBuf[SIGMA_I_SIG_DATA_OFFSET_CMAC], &leafCertHashCMacLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(leafCertHashCMacLen == 16);

    // Sha256(
    //    prefix || (se supported key size) || (host selected key size) || (se ephem pub key) || (host ephem pub key) || AES-CMAK_k_m1(prefix||leaf cert hash))
    // Or prefix || (se ephem pub key) || (host ephem pub key ) || AES-CMAC_k_tr(host leaf cert hash))
    status = sss_host_digest_context_init(&md, pSession, kAlgorithm_SSS_SHA256, kMode_SSS_Digest);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_digest_one_go(&md,
        (const uint8_t *)sigDataBuf,
        SIGMA_I_SIG_DATA_OFFSET_CMAC + leafCertHashCMacLen,
        sigDataDigest,
        &sigDataDigestLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    if (md.session != NULL) {
        sss_host_digest_context_free(&md);
    }

    // Sign sha256(Data)
    status = sss_host_asymmetric_context_init(
        &asym, pSession, &pAuthCtx->static_ctx.leafCertKeypair, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_asymmetric_sign_digest(&asym, sigDataDigest, sigDataDigestLen, asn1Sig, &asn1SigLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // C_k_i/C_k_r data = AEC_CCM_Enc_K_ei (host_leaf_cert_hash || Init/Resp_ECC_Sig)
    status = nx_decode_ASN1_signature(asn1Sig, asn1SigLen, ckDataBuf + NX_SHA256_BYTE_LEN, &compactSigLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    if (compactSigLen > (UINT_MAX - NX_SHA256_BYTE_LEN)) {
        LOG_E("C_k_r/C_k_i data length is wrapping");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    *ckDataBufLen = NX_SHA256_BYTE_LEN + compactSigLen;

exit:
    if (md.session != NULL) {
        sss_host_digest_context_free(&md);
    }
    if (macCtx.session != NULL) {
        sss_host_mac_context_free(&macCtx);
    }
    if (asym.session != NULL) {
        sss_host_asymmetric_context_free(&asym);
    }
    return status;
}

/**
 * @brief         Construct responder cert hash and signature C-APDU.
 *                Tx C-APDU.
 *
 *                C_k_r = AES_CCM_Enc_k_er(leaf_cert_hash || Init_ECC_Sig)
 *
 * @param         seSession          SE session
 * @param         pAuthCtx              Context Pointer to auth context.
 * @param         hostEpemPubkeyBuf     Host ephem public key.
 * @param         seEpemPubkeyBuf       SE ephem public key.
 * @param         pubkeyLen             Public key length.
 * @param[out]    respRAPDUBuf          Received R-APDU data.
 * @param[out]    pRespRAPDUBufLen      Received R-APDU data length.
 * @param[out]    respTag               Received R-APDU data tag.
 *
 * @return        Status.
 */
static sss_status_t nx_prover_Tx_cert_hash_sig(pSeSession_t seSession,
    nx_auth_sigma_ctx_t *pAuthCtx,
    uint8_t *hostEpemPubkeyBuf, // ASN.1 encoded
    uint8_t *seEpemPubkeyBuf,   // ASN.1 encoded
    size_t pubKeyLen,
    uint8_t *respTag,
    uint8_t *respRAPDUBuf,
    size_t *pRespRAPDUBufLen)
{
    sss_status_t status                                                 = kStatus_SSS_Fail;
    uint8_t ckrData[NX_SHA256_BYTE_LEN + NX_ECDSA_P256_SIG_BUFFER_SIZE] = {0}; // Data to be encrypted
    size_t ckrDataLen                                                   = sizeof(ckrData);
    uint8_t *pNonce                                                     = NULL;
    size_t nonceLen                                                     = 0;
    sss_object_t *pCCMKey                                               = NULL;
    uint8_t ckrValue[NX_SHA256_BYTE_LEN + 2 * NX_EC_PRIVATE_KEY_BYTE_LEN + NX_AES256_CCM_TAG_LENGH] = {
        0}; // (hash || sig) || tag
    uint8_t *encbuf     = &ckrValue[0];
    size_t encbufLen    = NX_SHA256_BYTE_LEN + 2 * NX_EC_PRIVATE_KEY_BYTE_LEN; // sha256+2*keylen
    uint8_t *tagBuf     = &ckrValue[NX_SHA256_BYTE_LEN + 2 * NX_EC_PRIVATE_KEY_BYTE_LEN];
    size_t tagLen       = NX_AES256_CCM_TAG_LENGH;
    uint8_t cmdBuf[256] = {0};
    uint8_t *pCmdBuf    = NULL;
    size_t cmdBufLen = 0, tmpCmdBufLen = 0;
    int tlvRet                          = 1;
    tlvHeader_t hdr                     = {{CLA_ISO7816, INS_GP_ISO_GENERAL_AUTHENTICATE, P1_SIGMA_I, 0}};
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP] = {0};
    uint8_t *pRspbuf                    = &rspbuf[0];
    size_t rspbufLen                    = sizeof(rspbuf);
    smStatus_t retStatus                = SM_NOT_OK;
    size_t asn1ECHdrLen                 = 0;
    uint8_t selectedKeySize             = 0;
    size_t rspIndex                     = 0;

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(hostEpemPubkeyBuf != NULL);
    ENSURE_OR_GO_EXIT(seEpemPubkeyBuf != NULL);
    ENSURE_OR_GO_EXIT(respRAPDUBuf != NULL);
    ENSURE_OR_GO_EXIT(pRespRAPDUBufLen != NULL);

    hdr.hdr[3] = pAuthCtx->static_ctx.seCertRepoId; // P2 is cert repo id.

    if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_BRAINPOOL) {
        asn1ECHdrLen = ASN_ECC_BP_256_HEADER_LEN;
    }
    else if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_NIST_P) {
        asn1ECHdrLen = ASN_ECC_NIST_256_HEADER_LEN;
    }
    else {
        goto exit;
    }

    ENSURE_OR_GO_EXIT(pubKeyLen == asn1ECHdrLen + 65);
    // C_k_r Data = host_leaf_cert_hash || Resp_ECC_Sig
    status =
        nx_prepare_host_c_k_data(pAuthCtx, false, hostEpemPubkeyBuf, seEpemPubkeyBuf, pubKeyLen, ckrData, &ckrDataLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // C_k_i = AES_CCM_Enc_k_e1(Data)
    pNonce   = pAuthCtx->dyn_ctx.iv_e1;
    nonceLen = sizeof(pAuthCtx->dyn_ctx.iv_e1);
    pCCMKey  = &pAuthCtx->dyn_ctx.k_e1;

    encbufLen = ckrDataLen; // sha256+2*keylen
    tagBuf    = &ckrValue[encbufLen];

    status = kStatus_SSS_Fail;
    status = nx_enc_AES256_CCM(pCCMKey, pNonce, nonceLen, ckrData, ckrDataLen, encbuf, &encbufLen, tagBuf, &tagLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // pAuthCtx->dyn_ctx.iv_s++ or iv_e1++;
    increase_big_data(pNonce, nonceLen);

    // Send cert hash and signature C-APDU
    if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES128_NTAG) {
        selectedKeySize = NX_SESSION_KEY_SIZE_BIT_AES128;
    }
    else if (pAuthCtx->dyn_ctx.selectedSecureTunnelType == knx_SecureSymmType_AES256_NTAG) {
        selectedKeySize = NX_SESSION_KEY_SIZE_BIT_AES256;
    }
    else {
        goto exit;
    }

    cmdBufLen    = 0;
    pCmdBuf      = &cmdBuf[3];
    tmpCmdBufLen = 0;
    // message: 83 xx <key size selected>
    tlvRet =
        TLVSET_U8("Host hash and sig", &pCmdBuf, &tmpCmdBufLen, NX_TAG_KEY_SIZE, selectedKeySize, sizeof(cmdBuf) - 3);
    ENSURE_OR_GO_EXIT(0 == tlvRet)
    ENSURE_OR_GO_EXIT(tmpCmdBufLen == 3);

    // message: 86 41 04 <yP, public key, 64 bytes>
    tlvRet = 1;
    tlvRet = TLVSET_u8buf("Host public key",
        &pCmdBuf,
        &tmpCmdBufLen,
        NX_TAG_EPHEM_PUB_KEY,
        &hostEpemPubkeyBuf[asn1ECHdrLen],
        65,
        sizeof(cmdBuf) - 3);
    ENSURE_OR_GO_EXIT(0 == tlvRet)
    ENSURE_OR_GO_EXIT(tmpCmdBufLen == (3 + 67));

    // message: 87 xx <c_k_r: encrypted hash and signature>
    tlvRet = 1;
    tlvRet = TLVSET_u8buf("Host hash and sig",
        &pCmdBuf,
        &tmpCmdBufLen,
        NX_TAG_ENCRYPTED_PAYLOAD,
        &ckrValue[0],
        encbufLen + tagLen,
        sizeof(cmdBuf) - 3);
    ENSURE_OR_GO_EXIT(0 == tlvRet)
    ENSURE_OR_GO_EXIT(tmpCmdBufLen == (3 + 67 + 106));
    cmdBufLen = tmpCmdBufLen;

    pCmdBuf      = &cmdBuf[0];
    tmpCmdBufLen = 0;
    // message:
    //  B1 81 A5
    //     83 01 <key size selected>
    //     86 41 04 <yP, public key, 64 bytes>
    //     87 60 <C_k_r: encrypted hash and signature>
    ENSURE_OR_GO_EXIT((UINT_MAX - encbufLen) >= tagLen);
    tlvRet = 1;
    tlvRet = TLVSET_u8buf("Host public key, hash and sig",
        &pCmdBuf,
        &tmpCmdBufLen,
        NX_TAG_MSGR_HASH_AND_SIG,
        &cmdBuf[3],
        cmdBufLen,
        sizeof(cmdBuf));
    ENSURE_OR_GO_EXIT(0 == tlvRet)
    ENSURE_OR_GO_EXIT(tmpCmdBufLen == (3 + 3 + 67 + 106));
    cmdBufLen = tmpCmdBufLen;

    retStatus = DoAPDUTxRx_s_Case4(seSession, &hdr, cmdBuf, cmdBufLen, NULL, 0, rspbuf, &rspbufLen, NULL);
    ENSURE_OR_GO_EXIT(retStatus == SM_OK);

    // Get SE encrypted certificate
    *respTag = rspbuf[0];

    ENSURE_OR_GO_EXIT((rspbuf[0] == NX_TAG_MSGI_CERT_REQUEST) || (rspbuf[0] == NX_TAG_MSGI_HASH_AND_SIG));

    if (rspbuf[0] == NX_TAG_MSGI_CERT_REQUEST) {
        ENSURE_OR_GO_EXIT(rspbufLen >= 4);
        // Cert request should always be A2 0C 87 0A
        ENSURE_OR_GO_EXIT((rspbuf[1] == 0x0C) && (rspbuf[2] == NX_TAG_ENCRYPTED_PAYLOAD) && (rspbuf[3] == 0x0A));
        rspIndex = 2;
    }

    tlvRet = tlvGet_u8buf(pRspbuf, &rspIndex, rspbufLen, rspbuf[rspIndex], respRAPDUBuf, pRespRAPDUBufLen);
    ENSURE_OR_GO_EXIT(0 == tlvRet)

    retStatus = SM_NOT_OK;
    if ((rspIndex + 2) == rspbufLen) {
        retStatus = (pRspbuf[rspIndex] << 8) | (pRspbuf[rspIndex + 1]);
    }
    ENSURE_OR_GO_EXIT(SM_OK == retStatus)

    status = kStatus_SSS_Success;
exit:
    return status;
}

sss_status_t nx_sigma_i_authenticate_channel(pSeSession_t seSession, nx_auth_sigma_ctx_t *pAuthCtx)
{
    sss_status_t status                                                             = kStatus_SSS_Fail;
    uint8_t rxPubKeyBuf[100]                                                        = {0};
    size_t rxPubKeyBufLen                                                           = sizeof(rxPubKeyBuf);
    uint8_t epemDERPubkey[100]                                                      = {0};
    size_t epemDERPubkeyLen                                                         = sizeof(epemDERPubkey);
    size_t epemPubkeyBitLen                                                         = 0;
    uint8_t *pEpemPubkeyBuf                                                         = NULL;
    uint8_t rxEncCertBuf[NX_MAX_CERT_BUFFER_SIZE]                                   = {0};
    uint8_t *pRxEncCertBuf                                                          = (uint8_t *)&rxEncCertBuf;
    size_t rxEncCertBufLen                                                          = NX_MAX_CERT_BUFFER_SIZE;
    uint8_t rxEncHashBuf[110]                                                       = {0};
    size_t rxEncHashBufLen                                                          = sizeof(rxEncHashBuf);
    uint8_t rxDecCertHashSigBuf[NX_SHA256_BYTE_LEN + NX_ECDSA_P256_SIG_BUFFER_SIZE] = {0};
    size_t rxDecCertHashSigBufLen                                                   = sizeof(rxDecCertHashSigBuf);
    uint8_t *pCertHashBuf                                                           = NULL;
    uint8_t *pCertSigBuf                                                            = NULL;
    size_t certHashBufLen                                                           = 0;
    size_t certSigBufLen                                                            = 0;
#ifdef EX_SSS_SIGMA_I_CACHE_FILE_DIR
    int cacheFound = -1;
#endif
    uint8_t *seCertBuf[3]                            = {0}; // Used for leaf/p1/p2 certificate
    size_t seCertBufBufLen[3]                        = {0};
    uint8_t *pCertBuf                                = NULL;
    size_t *pCertBufLen                              = NULL;
    nx_device_cert_ctx_host_t deviceCertCtx          = {0};
    uint8_t *deviceCACertCacheBuf[NX_MAX_CERT_DEPTH] = {0};
    bool validCert                                   = false;
    uint8_t rxEncCertReqBuf[150]                     = {0};
    size_t rxEncCertReqBufLen                        = sizeof(rxEncCertReqBuf);
    uint8_t rxSeCertReq[2]                           = {0};
    size_t rxSeCertReqLen                            = sizeof(rxSeCertReq);
    int count                                        = 0;
    uint8_t *respRAPDUBuf  = rxEncCertReqBuf; // Responder R-APDU buffer. Reuse rxEncCertReqBuf[]
    size_t respRAPDUBufLen = rxEncCertReqBufLen;
    uint8_t rxTagValue     = 0;
    int certIndex          = -1;
    size_t asn1ECHdrLen    = 0;
#if (defined SSS_HAVE_HOST_FRDMMCXA153 && SSS_HAVE_HOST_FRDMMCXA153)
    // seRootCert available as a global buffer for MCXA
#else
    uint8_t seRootCert[NX_MAX_CERT_BUFFER_SIZE] = {0};
#endif
    uint8_t *pSERootCert                         = (uint8_t *)&seRootCert;
    size_t seRootCertLen                         = NX_MAX_CERT_BUFFER_SIZE;
    int i                                        = -1;
    uint8_t publicKey[NX_PUBLIC_KEY_BUFFER_SIZE] = {0};
    size_t publicKeyLen                          = sizeof(publicKey);

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);

    memset(pRxEncCertBuf, 0, NX_MAX_CERT_BUFFER_SIZE);
    memset(pSERootCert, 0, NX_MAX_CERT_BUFFER_SIZE);

    // Initialize the certificate structures for hostcrypto operations
    nx_hostcrypto_cert_init(&deviceCertCtx);

    status = nx_get_se_root_cert(pAuthCtx->dyn_ctx.hostEphemCurveType, pSERootCert, &seRootCertLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_MAU8_D("Device Root Certificate", pSERootCert, seRootCertLen);

    status = kStatus_SSS_Fail; // Reinitializing exit status

    // Buffer used for SE certificates
    for (certIndex = NX_CERT_LEVEL_LEAF; certIndex <= NX_MAX_CERT_DEPTH; certIndex++) {
        seCertBuf[certIndex - 1] = (uint8_t *)SSS_MALLOC(NX_MAX_CERT_BUFFER_SIZE);
        ENSURE_OR_GO_EXIT(seCertBuf[certIndex - 1] != NULL);
        memset(seCertBuf[certIndex - 1], 0, NX_MAX_CERT_BUFFER_SIZE);
        seCertBufBufLen[certIndex - 1] = NX_MAX_CERT_BUFFER_SIZE;
    }

    if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_BRAINPOOL) {
        asn1ECHdrLen = ASN_ECC_BP_256_HEADER_LEN;
    }
    else if (pAuthCtx->dyn_ctx.hostEphemCurveType == kSSS_CipherType_EC_NIST_P) {
        asn1ECHdrLen = ASN_ECC_NIST_256_HEADER_LEN;
    }
    else {
        goto exit;
    }

    // Get Host Ephemeral public key
    status = sss_host_key_store_get_key(pAuthCtx->static_ctx.ephemKeypair.keyStore,
        &pAuthCtx->static_ctx.ephemKeypair,
        epemDERPubkey,
        &epemDERPubkeyLen,
        &epemPubkeyBitLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(epemDERPubkeyLen == NX_PUBLIC_KEY_LENGTH + asn1ECHdrLen);

    pEpemPubkeyBuf = &epemDERPubkey[asn1ECHdrLen];
    LOG_MAU8_D("Sending Host ephm public key", pEpemPubkeyBuf, epemDERPubkeyLen - asn1ECHdrLen);

    if (seSession->authType == knx_AuthType_SIGMA_I_Verifier) {
        // Tx Host Public key C-APDU
        status = nx_verifier_Tx_init_pub_key(seSession,
            pAuthCtx,
            epemDERPubkey,
            epemDERPubkeyLen,
            rxPubKeyBuf,
            &rxPubKeyBufLen,
            rxEncHashBuf,
            &rxEncHashBufLen);
        if (status != kStatus_SSS_Success) {
            LOG_E("Certificate and Keys may not be provisioned. (Please run nx_Personalization example.)");
            goto exit;
        }
        ENSURE_OR_GO_EXIT(rxPubKeyBufLen == NX_PUBLIC_KEY_LENGTH + asn1ECHdrLen);

        // Make a sanity check on the received ephemeral public key
        status = nx_hostcrypto_validate_pubkey(
            rxPubKeyBuf + asn1ECHdrLen, rxPubKeyBufLen - asn1ECHdrLen, pAuthCtx->dyn_ctx.hostEphemCurveType);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        // Set SE ephem public key
        status = sss_host_key_store_set_key(pAuthCtx->static_ctx.seEphemPubKey.keyStore,
            &(pAuthCtx->static_ctx.seEphemPubKey),
            rxPubKeyBuf,
            rxPubKeyBufLen,
            256,
            NULL,
            0);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        // Create session keys and nonce
        // pEpemPubkeyBuf[1]: Remove 04
        // rxPubKeyBuf[ASN_ECC_HEADER_LEN+1]: Remove ASN header
        status = nx_generate_session_keys_and_nonce(pAuthCtx, &pEpemPubkeyBuf[1], &rxPubKeyBuf[asn1ECHdrLen + 1]);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        // Get decrypted cert hash and signature.

        LOG_MAU8_D("Encrypted (Cert hash + Signature)", rxEncHashBuf, rxEncHashBufLen);
        status = nx_get_leaf_cert_hash(
            pAuthCtx, true, rxEncHashBuf, rxEncHashBufLen, rxDecCertHashSigBuf, &rxDecCertHashSigBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        LOG_MAU8_D("Decrypted (Cert hash + Signature)", rxDecCertHashSigBuf, rxDecCertHashSigBufLen);

        // cert hash | cert signature
        status = kStatus_SSS_Fail;
        ENSURE_OR_GO_EXIT(rxDecCertHashSigBufLen > NX_SHA256_BYTE_LEN);
        pCertHashBuf   = &rxDecCertHashSigBuf[0];
        certHashBufLen = NX_SHA256_BYTE_LEN;
        pCertSigBuf    = &rxDecCertHashSigBuf[NX_SHA256_BYTE_LEN];
        certSigBufLen  = rxDecCertHashSigBufLen - certHashBufLen;

        LOG_MAU8_D("Device leaf cert hash", pCertHashBuf, certHashBufLen);
        LOG_MAU8_D("Device ECC signature", pCertSigBuf, certSigBufLen);

#ifdef EX_SSS_SIGMA_I_CACHE_FILE_DIR
        // Looking for cert hash in cache
        cacheFound = NX_LEAF_CERT_CACHE_ITEM_NA;
        if (pAuthCtx->dyn_ctx.hostCacheType == knx_AuthCache_Enabled) {
            ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_find_hash_from_cache != NULL);
            status = pAuthCtx->static_ctx.fp_find_hash_from_cache(pCertHashBuf, certHashBufLen, &cacheFound);
            ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
        }
        if (NX_LEAF_CERT_CACHE_ITEM_NA == cacheFound) {
#endif
            // Cert not cached. Require certificate from SE.
            validCert = false;
            for (certIndex = NX_CERT_LEVEL_LEAF; certIndex <= NX_MAX_CERT_DEPTH; certIndex++) {
                rxEncCertBufLen = NX_MAX_CERT_BUFFER_SIZE;
                memset(pRxEncCertBuf, 0, rxEncCertBufLen);
                status = nx_Tx_cert_request(seSession, pAuthCtx, certIndex, true, pRxEncCertBuf, &rxEncCertBufLen);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                LOG_D("Certificate Level - %d", certIndex);
                LOG_MAU8_D("Encrypted certificate", pRxEncCertBuf, rxEncCertBufLen);

                // Get responder cert from encrypted certificate
                pCertBuf     = seCertBuf[certIndex - 1];
                pCertBufLen  = &seCertBufBufLen[certIndex - 1];
                *pCertBufLen = NX_MAX_CERT_BUFFER_SIZE;
                memset(pCertBuf, 0, seCertBufBufLen[certIndex - 1]);

                // Decrypt using ke1, ive1
                status = nx_decrypt_certificate(
                    pAuthCtx, certIndex, true, pRxEncCertBuf, rxEncCertBufLen, pCertBuf, pCertBufLen);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                LOG_MAU8_D("Decrypted device certificate", pCertBuf, *pCertBufLen);

                // Parse leaf/p1/p2 pkcs7 certificate and add it to container.
                status =
                    nx_hostcrypto_parse_x509_cert(&deviceCertCtx, kDeviceCert, certIndex - 1, pCertBuf, *pCertBufLen);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                if (certIndex == NX_CERT_LEVEL_LEAF) {
                    // Get leaf public key from leaf cert and set to key obj.
                    status = nx_hostcrypto_get_pubkey_from_cert(&deviceCertCtx, publicKey, &publicKeyLen);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                    status = nx_set_cert_pk(pAuthCtx, publicKey, publicKeyLen);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                    // Calculate leaf cert hash and compared to received one.
                    status = nx_verify_leaf_cert_hash(pAuthCtx, pCertHashBuf, certHashBufLen, pCertBuf, *pCertBufLen);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                    // Verify leaf cert hash signature.
                    status = nx_verify_leaf_cert_hash_signature(pAuthCtx,
                        true,
                        pCertHashBuf,
                        certHashBufLen,
                        pCertSigBuf,
                        certSigBufLen,
                        epemDERPubkey,
                        rxPubKeyBuf,
                        epemDERPubkeyLen);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                    // Init device root certificate and cached CA cert as container.
                    status = nx_hostcrypto_get_CA_cert_list(
                        pAuthCtx, &deviceCertCtx, pSERootCert, seRootCertLen, deviceCACertCacheBuf);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                }
                else {
                    // Add to intermediate certificate chain
                    status = nx_hostcrypto_push_intermediate_cert(&deviceCertCtx, certIndex - 1);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                }

                // Verify leaf/p1/p2 cert signature.
                status = nx_hostcrypto_verify_x509_cert(&deviceCertCtx, &validCert);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                if (validCert == true)
                    break;
            }

            status = kStatus_SSS_Fail;
            ENSURE_OR_GO_EXIT(validCert == true);

#ifdef EX_SSS_SIGMA_I_CACHE_FILE_DIR
            if (pAuthCtx->dyn_ctx.hostCacheType == knx_AuthCache_Enabled) {
                // Cache device leaf cert hash and public key
                status = nx_leaf_cert_cache_insert(pAuthCtx, pCertHashBuf, certHashBufLen);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                status = kStatus_SSS_Fail;
                ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_insert_parent_cert_to_cache != NULL);

                // Cache P1 cert
                if (certIndex >= NX_CERT_LEVEL_P1) {
                    // ex_parent_cert_cache_insert
                    status = pAuthCtx->static_ctx.fp_insert_parent_cert_to_cache(
                        seCertBuf[NX_CERT_LEVEL_P1 - 1], seCertBufBufLen[NX_CERT_LEVEL_P1 - 1]);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                }

                // Cache P2 cert
                if (certIndex >= NX_CERT_LEVEL_P2) {
                    // ex_parent_cert_cache_insert
                    status = pAuthCtx->static_ctx.fp_insert_parent_cert_to_cache(
                        seCertBuf[NX_CERT_LEVEL_P2 - 1], seCertBufBufLen[NX_CERT_LEVEL_P2 - 1]);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                }
            }
        }
        else {
            // Found cache. Set public key and verify the signature.
            if (cacheFound < 0) {
                status = kStatus_SSS_Fail;
                goto exit;
            }

            // ex_get_pk_from_cache()
            status = kStatus_SSS_Fail;
            ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_get_pk_from_cache != NULL);
            status = pAuthCtx->static_ctx.fp_get_pk_from_cache(cacheFound, publicKey, &publicKeyLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            status = nx_set_cert_pk(pAuthCtx, publicKey, publicKeyLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            // Verify leaf cert hash signature.
            status = nx_verify_leaf_cert_hash_signature(pAuthCtx,
                true,
                pCertHashBuf,
                certHashBufLen,
                pCertSigBuf,
                certSigBufLen,
                epemDERPubkey,
                rxPubKeyBuf,
                epemDERPubkeyLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        }
#endif
        // Cert hash and signature C-APDU
        status = nx_verifier_Tx_cert_hash_sig(seSession,
            pAuthCtx,
            epemDERPubkey,
            rxPubKeyBuf,
            epemDERPubkeyLen,
            &rxTagValue,
            rxEncCertReqBuf,
            &rxEncCertReqBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        while (rxTagValue != NX_TAG_MSG_SESSION_OK) {
            // Should not exceed 3 times (Host leaf/p1/p2 certificate).
            if (count > 3) {
                LOG_E("Device require too many certificates");
                status = kStatus_SSS_Fail;
                break;
            }

            status = nx_decrypt_se_cert_req(
                pAuthCtx, rxEncCertReqBuf, rxEncCertReqBufLen, true, rxSeCertReq, &rxSeCertReqLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            rxEncCertReqBufLen = sizeof(rxEncCertReqBuf);
            status             = nx_Tx_cert_reply_sig(seSession,
                pAuthCtx,
                rxSeCertReq,
                rxSeCertReqLen,
                true,
                &rxTagValue,
                rxEncCertReqBuf,
                &rxEncCertReqBufLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            count++;
        }

        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        pAuthCtx->dyn_ctx.authType = knx_AuthType_SIGMA_I_Verifier;
    }
    else if (seSession->authType == knx_AuthType_SIGMA_I_Prover) {
        status = nx_prover_Tx_control_transfer(seSession, pAuthCtx, rxPubKeyBuf, &rxPubKeyBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        ENSURE_OR_GO_EXIT(rxPubKeyBufLen == NX_PUBLIC_KEY_LENGTH + asn1ECHdrLen);

        // Make a sanity check on the received ephemeral public key
        status = nx_hostcrypto_validate_pubkey(
            rxPubKeyBuf + asn1ECHdrLen, rxPubKeyBufLen - asn1ECHdrLen, pAuthCtx->dyn_ctx.hostEphemCurveType);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        // Set SE ephem public key
        status = sss_host_key_store_set_key(pAuthCtx->static_ctx.seEphemPubKey.keyStore,
            &(pAuthCtx->static_ctx.seEphemPubKey),
            rxPubKeyBuf,
            rxPubKeyBufLen,
            256,
            NULL,
            0);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        // Create session keys and nonce
        // pEpemPubkeyBuf[1]: Remove 04
        // rxPubKeyBuf[ASN_ECC_HEADER_LEN+1]: Remove ASN header
        status = nx_generate_session_keys_and_nonce(pAuthCtx, &rxPubKeyBuf[asn1ECHdrLen + 1], &pEpemPubkeyBuf[1]);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        status = kStatus_SSS_Fail;
        ENSURE_OR_GO_EXIT(rxPubKeyBufLen == epemDERPubkeyLen);

        // Tx responder public key, cert hash and signature
        status = nx_prover_Tx_cert_hash_sig(seSession,
            pAuthCtx,
            epemDERPubkey,
            rxPubKeyBuf,
            epemDERPubkeyLen,
            &rxTagValue,
            respRAPDUBuf,
            &respRAPDUBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        count = 0;
        while (rxTagValue != NX_TAG_MSGI_HASH_AND_SIG) {
            // Should not exceed 3 times (Host leaf/p1/p2 certificate).
            if (count > 3) {
                LOG_E("Device require too many certificates");
                status = kStatus_SSS_Fail;
                break;
            }

            // Receive Initiator Cert request.
            status =
                nx_decrypt_se_cert_req(pAuthCtx, respRAPDUBuf, respRAPDUBufLen, false, rxSeCertReq, &rxSeCertReqLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            respRAPDUBufLen = sizeof(rxEncCertReqBuf);
            status          = nx_Tx_cert_reply_sig(
                seSession, pAuthCtx, rxSeCertReq, rxSeCertReqLen, false, &rxTagValue, respRAPDUBuf, &respRAPDUBufLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        }

        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        // Receive Cert hash and signature.

        // Get decrypted cert hash and signature.
        status = nx_get_leaf_cert_hash(
            pAuthCtx, false, respRAPDUBuf, respRAPDUBufLen, rxDecCertHashSigBuf, &rxDecCertHashSigBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        // cert hash | cert signature
        pCertHashBuf   = &rxDecCertHashSigBuf[0];
        certHashBufLen = NX_SHA256_BYTE_LEN;
        pCertSigBuf    = &rxDecCertHashSigBuf[NX_SHA256_BYTE_LEN];
        certSigBufLen  = rxDecCertHashSigBufLen - certHashBufLen;

#ifdef EX_SSS_SIGMA_I_CACHE_FILE_DIR
        // Looking for cert hash in cashe
        cacheFound = NX_LEAF_CERT_CACHE_ITEM_NA;
        if (pAuthCtx->dyn_ctx.hostCacheType == knx_AuthCache_Enabled) {
            ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_find_hash_from_cache != NULL);
            // ex_find_hash_in_cache()
            status = pAuthCtx->static_ctx.fp_find_hash_from_cache(pCertHashBuf, certHashBufLen, &cacheFound);
            ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status)
        }

        if (NX_LEAF_CERT_CACHE_ITEM_NA == cacheFound) {
#endif
            // Cert not cached. Require certificate from SE.

            validCert = false;
            for (certIndex = NX_CERT_LEVEL_LEAF; certIndex <= NX_MAX_CERT_DEPTH; certIndex++) {
                rxEncCertBufLen = NX_MAX_CERT_BUFFER_SIZE;
                memset(pRxEncCertBuf, 0, rxEncCertBufLen);
                status = nx_Tx_cert_request(seSession, pAuthCtx, certIndex, false, pRxEncCertBuf, &rxEncCertBufLen);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                // Get responder cert from encrypted certificate
                pCertBuf     = seCertBuf[certIndex - 1];
                pCertBufLen  = &seCertBufBufLen[certIndex - 1];
                *pCertBufLen = NX_MAX_CERT_BUFFER_SIZE;
                memset(pCertBuf, 0, seCertBufBufLen[certIndex - 1]);

                status = nx_decrypt_certificate(
                    pAuthCtx, certIndex, false, pRxEncCertBuf, rxEncCertBufLen, pCertBuf, pCertBufLen);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                // Parse leaf/p1/p2 pkcs7 certificate and add it to container.
                status =
                    nx_hostcrypto_parse_x509_cert(&deviceCertCtx, kDeviceCert, certIndex - 1, pCertBuf, *pCertBufLen);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                if (certIndex == NX_CERT_LEVEL_LEAF) {
                    // Get leaf public key from leaf cert and set to key obj.
                    status = nx_hostcrypto_get_pubkey_from_cert(&deviceCertCtx, publicKey, &publicKeyLen);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                    status = nx_set_cert_pk(pAuthCtx, publicKey, publicKeyLen);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                    // Calculate leaf cert hash and compared to received one.
                    status = nx_verify_leaf_cert_hash(pAuthCtx, pCertHashBuf, certHashBufLen, pCertBuf, *pCertBufLen);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                    // Verify leaf cert hash signature.
                    status = nx_verify_leaf_cert_hash_signature(pAuthCtx,
                        false,
                        pCertHashBuf,
                        certHashBufLen,
                        pCertSigBuf,
                        certSigBufLen,
                        epemDERPubkey,
                        rxPubKeyBuf,
                        epemDERPubkeyLen);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                    // Init device root certificate and cached CA cert as container.
                    status = nx_hostcrypto_get_CA_cert_list(
                        pAuthCtx, &deviceCertCtx, pSERootCert, seRootCertLen, deviceCACertCacheBuf);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                }
                else {
                    // Add to intermediate certificate chain
                    status = nx_hostcrypto_push_intermediate_cert(&deviceCertCtx, certIndex - 1);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                }

                // Verify leaf/p1/p2 cert signature.
                status = nx_hostcrypto_verify_x509_cert(&deviceCertCtx, &validCert);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                if (validCert == true) {
                    break;
                }
            }

            status = kStatus_SSS_Fail;
            ENSURE_OR_GO_EXIT(validCert == true);

#ifdef EX_SSS_SIGMA_I_CACHE_FILE_DIR
            if (pAuthCtx->dyn_ctx.hostCacheType == knx_AuthCache_Enabled) {
                // Cache device leaf cert hash and public key
                status = nx_leaf_cert_cache_insert(pAuthCtx, pCertHashBuf, certHashBufLen);
                ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

                status = kStatus_SSS_Fail;
                ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_insert_parent_cert_to_cache != NULL);

                // Cache P1 cert
                if (certIndex >= NX_CERT_LEVEL_P1) {
                    // ex_parent_cert_cache_insert
                    status = pAuthCtx->static_ctx.fp_insert_parent_cert_to_cache(
                        seCertBuf[NX_CERT_LEVEL_P1 - 1], seCertBufBufLen[NX_CERT_LEVEL_P1 - 1]);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                }

                // Cache P2 cert
                if (certIndex >= NX_CERT_LEVEL_P2) {
                    // ex_parent_cert_cache_insert
                    status = pAuthCtx->static_ctx.fp_insert_parent_cert_to_cache(
                        seCertBuf[NX_CERT_LEVEL_P2 - 1], seCertBufBufLen[NX_CERT_LEVEL_P2 - 1]);
                    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
                }
            }
            else {
                status = kStatus_SSS_Success;
            }
        }
        else {
            // Found cache. Set public key and verify the signature.
            if (cacheFound < 0) {
                status = kStatus_SSS_Fail;
                goto exit;
            }

            // ex_get_pk_from_cache()
            status = kStatus_SSS_Fail;
            ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_get_pk_from_cache != NULL);
            status = pAuthCtx->static_ctx.fp_get_pk_from_cache(cacheFound, publicKey, &publicKeyLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            status = nx_set_cert_pk(pAuthCtx, publicKey, publicKeyLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            // Verify leaf cert hash signature.
            status = nx_verify_leaf_cert_hash_signature(pAuthCtx,
                false,
                pCertHashBuf,
                certHashBufLen,
                pCertSigBuf,
                certSigBufLen,
                epemDERPubkey,
                rxPubKeyBuf,
                epemDERPubkeyLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        }
#endif
        pAuthCtx->dyn_ctx.authType = knx_AuthType_SIGMA_I_Prover;
    }

    status = kStatus_SSS_Success;
exit:
    nx_hostcrypto_cert_free(&deviceCertCtx);

    for (i = 0; i < NX_MAX_CERT_DEPTH; i++) {
        if (deviceCACertCacheBuf[i] != NULL) {
            SSS_FREE(deviceCACertCacheBuf[i]);
        }
    }

    for (certIndex = NX_CERT_LEVEL_LEAF; certIndex <= NX_MAX_CERT_DEPTH; certIndex++) {
        if (seCertBuf[certIndex - 1] != NULL) {
            SSS_FREE(seCertBuf[certIndex - 1]);
        }
    }

    return status;
}
#endif // SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER

#if (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))

#if (defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
static sss_status_t symm_auth_derive_AES128_session_keys(nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndA, uint8_t *RndB)
{
    sss_status_t status = kStatus_SSS_Fail;

    uint8_t SV1[NX_SYMM_AUTH_SESSION_VECTOR_LEN] = {0};
    uint8_t SV2[NX_SYMM_AUTH_SESSION_VECTOR_LEN] = {0};
    uint8_t SV1_part1[NX_SYMM_AUTH_SV_PART1_LEN] = NX_SYMM_AUTH_SV1_PART;
    uint8_t SV2_part1[NX_SYMM_AUTH_SV_PART1_LEN] = NX_SYMM_AUTH_SV2_PART;

    uint8_t RndA15_14[NX_SYMM_AUTH_RNDA15_14_BUF_LEN]  = {0};
    uint8_t RndA13_8[NX_SYMM_AUTH_RNDA13_8_BUF_LEN]    = {0};
    uint8_t RndB15_10[NX_SYMM_AUTH_RNDB15_10_BUF_LEN]  = {0};
    uint8_t RndB9_0[NX_SYMM_AUTH_RNDB9_0_BUF_LEN]      = {0};
    uint8_t RndA7_0[NX_SYMM_AUTH_RNDA7_0_BUF_LEN]      = {0};
    uint8_t XorResult[NX_SYMM_AUTH_XOR_RESULT_BUF_LEN] = {0};
    uint8_t macToAdd[NX_SYMM_AUTH_MACDATA_BUF_SIZE]    = {0};
    size_t macLen                                      = sizeof(macToAdd);
    uint8_t dataToMAC[NX_SYMM_AUTH_DATATOMAC_BUF_SIZE] = {0};
    size_t dataToMACLen                                = sizeof(dataToMAC);
    uint8_t sv_offset                                  = 0;
    size_t keyBitLen                                   = 0;

    ENSURE_OR_GO_EXIT(NULL != pAuthCtx);
    ENSURE_OR_GO_EXIT(NULL != RndA);
    ENSURE_OR_GO_EXIT(NULL != RndB);

    if (pAuthCtx->static_ctx.appKeySize > UINT_MAX / 8) {
        goto exit;
    }
    keyBitLen            = (pAuthCtx->static_ctx.appKeySize * 8);
    sss_object_t *appKey = NULL;
    appKey               = &pAuthCtx->static_ctx.appKey;

    memcpy(RndA7_0, RndA + 8, NX_SYMM_AUTH_RNDA7_0_BUF_LEN);
    memcpy(RndA13_8, RndA + 2, NX_SYMM_AUTH_RNDA13_8_BUF_LEN);
    memcpy(RndA15_14, RndA, NX_SYMM_AUTH_RNDA15_14_BUF_LEN);
    memcpy(RndB15_10, RndB, NX_SYMM_AUTH_RNDB15_10_BUF_LEN);
    memcpy(RndB9_0, RndB + 6, NX_SYMM_AUTH_RNDB9_0_BUF_LEN);

    XorResult[0] = (RndA13_8[0] ^ RndB15_10[0]);
    XorResult[1] = (RndA13_8[1] ^ RndB15_10[1]);
    XorResult[2] = (RndA13_8[2] ^ RndB15_10[2]);
    XorResult[3] = (RndA13_8[3] ^ RndB15_10[3]);
    XorResult[4] = (RndA13_8[4] ^ RndB15_10[4]);
    XorResult[5] = (RndA13_8[5] ^ RndB15_10[5]);

    memcpy(SV1, SV1_part1, NX_SYMM_AUTH_SV_PART1_LEN);
    sv_offset = NX_SYMM_AUTH_SV_PART1_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA15_14_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1 + sv_offset, RndA15_14, NX_SYMM_AUTH_RNDA15_14_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDA15_14_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_XOR_RESULT_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1 + sv_offset, XorResult, NX_SYMM_AUTH_XOR_RESULT_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_XOR_RESULT_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDB9_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1 + sv_offset, RndB9_0, NX_SYMM_AUTH_RNDB9_0_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDB9_0_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA7_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1 + sv_offset, RndA7_0, NX_SYMM_AUTH_RNDA7_0_BUF_LEN);

    sv_offset = 0;
    memcpy(SV2, SV2_part1, NX_SYMM_AUTH_SV_PART1_LEN);
    sv_offset = NX_SYMM_AUTH_SV_PART1_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA15_14_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2 + sv_offset, RndA15_14, NX_SYMM_AUTH_RNDA15_14_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDA15_14_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_XOR_RESULT_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2 + sv_offset, XorResult, NX_SYMM_AUTH_XOR_RESULT_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_XOR_RESULT_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDB9_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2 + sv_offset, RndB9_0, NX_SYMM_AUTH_RNDB9_0_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDB9_0_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA7_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2 + sv_offset, RndA7_0, NX_SYMM_AUTH_RNDA7_0_BUF_LEN);

    memcpy(dataToMAC, SV1, NX_SYMM_AUTH_SESSION_VECTOR_LEN);

    status = host_do_mac(appKey, dataToMAC, dataToMACLen, macToAdd, macLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_key_store_set_key(
        pAuthCtx->dyn_ctx.k_e2.keyStore, &pAuthCtx->dyn_ctx.k_e2, macToAdd, macLen, keyBitLen, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    memset(dataToMAC, 0x00, dataToMACLen);

    memcpy(dataToMAC, SV2, dataToMACLen);

    status = host_do_mac(appKey, dataToMAC, dataToMACLen, macToAdd, macLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_key_store_set_key(
        pAuthCtx->dyn_ctx.k_m2.keyStore, &pAuthCtx->dyn_ctx.k_m2, macToAdd, macLen, keyBitLen, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2

#if (defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2)) || \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
static sss_status_t symm_auth_derive_AES256_session_keys(nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndA, uint8_t *RndB)
{
    sss_status_t status = kStatus_SSS_Fail;

    uint8_t SV1a[NX_SYMM_AUTH_SESSION_VECTOR_LEN] = {0};
    uint8_t SV1b[NX_SYMM_AUTH_SESSION_VECTOR_LEN] = {0};
    uint8_t SV2a[NX_SYMM_AUTH_SESSION_VECTOR_LEN] = {0};
    uint8_t SV2b[NX_SYMM_AUTH_SESSION_VECTOR_LEN] = {0};
    uint8_t SV1a_part1[NX_SYMM_AUTH_SV_PART1_LEN] = NX_SYMM_AUTH_SV1A_PART1;
    uint8_t SV1b_part1[NX_SYMM_AUTH_SV_PART1_LEN] = NX_SYMM_AUTH_SV1B_PART1;
    uint8_t SV2a_part1[NX_SYMM_AUTH_SV_PART1_LEN] = NX_SYMM_AUTH_SV2A_PART1;
    uint8_t SV2b_part1[NX_SYMM_AUTH_SV_PART1_LEN] = NX_SYMM_AUTH_SV2B_PART1;

    uint8_t RndA15_14[NX_SYMM_AUTH_RNDA15_14_BUF_LEN]  = {0};
    uint8_t RndA13_8[NX_SYMM_AUTH_RNDA13_8_BUF_LEN]    = {0};
    uint8_t RndB15_10[NX_SYMM_AUTH_RNDB15_10_BUF_LEN]  = {0};
    uint8_t RndB9_0[NX_SYMM_AUTH_RNDB9_0_BUF_LEN]      = {0};
    uint8_t RndA7_0[NX_SYMM_AUTH_RNDA7_0_BUF_LEN]      = {0};
    uint8_t XorResult[NX_SYMM_AUTH_XOR_RESULT_BUF_LEN] = {0};
    uint8_t macToAdd[NX_SYMM_AUTH_MACDATA_BUF_SIZE]    = {0};
    size_t macLen                                      = sizeof(macToAdd);
    uint8_t dataToMAC[NX_SYMM_AUTH_DATATOMAC_BUF_SIZE] = {0};
    size_t dataToMACLen                                = sizeof(dataToMAC);

    uint8_t sv_offset = 0;
    size_t keyBitLen  = 0;

    uint8_t keyDataBuf[NX_SYMM_AUTH_AES256_KEY_SIZE] = {0};
    size_t keyDataBufLen                             = sizeof(keyDataBuf);
    size_t keyDataOffSet                             = 0;
    sss_object_t *appKey                             = NULL;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    keyBitLen = (pAuthCtx->static_ctx.appKeySize * 8);
    appKey    = &pAuthCtx->static_ctx.appKey;

    memcpy(RndA7_0, RndA + 8, NX_SYMM_AUTH_RNDA7_0_BUF_LEN);
    memcpy(RndA13_8, RndA + 2, NX_SYMM_AUTH_RNDA13_8_BUF_LEN);
    memcpy(RndA15_14, RndA, NX_SYMM_AUTH_RNDA15_14_BUF_LEN);
    memcpy(RndB15_10, RndB, NX_SYMM_AUTH_RNDB15_10_BUF_LEN);
    memcpy(RndB9_0, RndB + 6, NX_SYMM_AUTH_RNDB9_0_BUF_LEN);

    XorResult[0] = (RndA13_8[0] ^ RndB15_10[0]);
    XorResult[1] = (RndA13_8[1] ^ RndB15_10[1]);
    XorResult[2] = (RndA13_8[2] ^ RndB15_10[2]);
    XorResult[3] = (RndA13_8[3] ^ RndB15_10[3]);
    XorResult[4] = (RndA13_8[4] ^ RndB15_10[4]);
    XorResult[5] = (RndA13_8[5] ^ RndB15_10[5]);

    memcpy(SV1a, SV1a_part1, NX_SYMM_AUTH_SV_PART1_LEN);
    sv_offset = NX_SYMM_AUTH_SV_PART1_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA15_14_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1a + sv_offset, RndA15_14, NX_SYMM_AUTH_RNDA15_14_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDA15_14_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_XOR_RESULT_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1a + sv_offset, XorResult, NX_SYMM_AUTH_XOR_RESULT_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_XOR_RESULT_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDB9_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1a + sv_offset, RndB9_0, NX_SYMM_AUTH_RNDB9_0_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDB9_0_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA7_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1a + sv_offset, RndA7_0, NX_SYMM_AUTH_RNDA7_0_BUF_LEN);

    sv_offset = 0;
    memcpy(SV1b, SV1b_part1, NX_SYMM_AUTH_SV_PART1_LEN);
    sv_offset = NX_SYMM_AUTH_SV_PART1_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA15_14_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1b + sv_offset, RndA15_14, NX_SYMM_AUTH_RNDA15_14_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDA15_14_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_XOR_RESULT_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1b + sv_offset, XorResult, NX_SYMM_AUTH_XOR_RESULT_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_XOR_RESULT_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDB9_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1b + sv_offset, RndB9_0, NX_SYMM_AUTH_RNDB9_0_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDB9_0_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA7_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV1b + sv_offset, RndA7_0, NX_SYMM_AUTH_RNDA7_0_BUF_LEN);

    sv_offset = 0;
    memcpy(SV2a, SV2a_part1, NX_SYMM_AUTH_SV_PART1_LEN);
    sv_offset = NX_SYMM_AUTH_SV_PART1_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA15_14_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2a + sv_offset, RndA15_14, NX_SYMM_AUTH_RNDA15_14_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDA15_14_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_XOR_RESULT_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2a + sv_offset, XorResult, NX_SYMM_AUTH_XOR_RESULT_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_XOR_RESULT_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDB9_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2a + sv_offset, RndB9_0, NX_SYMM_AUTH_RNDB9_0_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDB9_0_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA7_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2a + sv_offset, RndA7_0, NX_SYMM_AUTH_RNDA7_0_BUF_LEN);

    sv_offset = 0;
    memcpy(SV2b, SV2b_part1, NX_SYMM_AUTH_SV_PART1_LEN);
    sv_offset = NX_SYMM_AUTH_SV_PART1_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA15_14_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2b + sv_offset, RndA15_14, NX_SYMM_AUTH_RNDA15_14_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDA15_14_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_XOR_RESULT_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2b + sv_offset, XorResult, NX_SYMM_AUTH_XOR_RESULT_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_XOR_RESULT_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDB9_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2b + sv_offset, RndB9_0, NX_SYMM_AUTH_RNDB9_0_BUF_LEN);
    sv_offset += NX_SYMM_AUTH_RNDB9_0_BUF_LEN;

    ENSURE_OR_GO_EXIT((sv_offset + NX_SYMM_AUTH_RNDA7_0_BUF_LEN) <= NX_SYMM_AUTH_SESSION_VECTOR_LEN);
    memcpy(SV2b + sv_offset, RndA7_0, NX_SYMM_AUTH_RNDA7_0_BUF_LEN);

    memcpy(dataToMAC, SV1a, dataToMACLen);

    status = host_do_mac(appKey, dataToMAC, dataToMACLen, macToAdd, macLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    memcpy(keyDataBuf, macToAdd, macLen);
    keyDataOffSet = macLen;
    memset(dataToMAC, 0x00, dataToMACLen);

    memcpy(dataToMAC, SV1b, dataToMACLen);

    status = host_do_mac(appKey, dataToMAC, dataToMACLen, macToAdd, macLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    ENSURE_OR_GO_EXIT((keyDataOffSet + macLen) <= NX_SYMM_AUTH_AES256_KEY_SIZE);
    memcpy(keyDataBuf + keyDataOffSet, macToAdd, macLen);

    status = sss_host_key_store_set_key(
        pAuthCtx->dyn_ctx.k_e2.keyStore, &pAuthCtx->dyn_ctx.k_e2, keyDataBuf, keyDataBufLen, keyBitLen, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    memset(keyDataBuf, 0x00, keyDataBufLen);
    keyDataOffSet = 0;
    memset(dataToMAC, 0x00, dataToMACLen);

    memcpy(dataToMAC, SV2a, dataToMACLen);
    status = host_do_mac(appKey, dataToMAC, dataToMACLen, macToAdd, macLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    memcpy(keyDataBuf, macToAdd, macLen);
    keyDataOffSet = macLen;
    memset(dataToMAC, 0x00, dataToMACLen);
    memcpy(dataToMAC, SV2b, dataToMACLen);

    status = host_do_mac(appKey, dataToMAC, dataToMACLen, macToAdd, macLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    ENSURE_OR_GO_EXIT((keyDataOffSet + macLen) <= NX_SYMM_AUTH_AES256_KEY_SIZE);
    memcpy(keyDataBuf + keyDataOffSet, macToAdd, macLen);

    status = sss_host_key_store_set_key(
        pAuthCtx->dyn_ctx.k_m2.keyStore, &pAuthCtx->dyn_ctx.k_m2, keyDataBuf, keyDataBufLen, keyBitLen, NULL, 0);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

exit:
    return status;
}
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2

static sss_status_t host_symmetric_decrypt(
    sss_object_t *appKey, uint8_t *dataToDecrypt, size_t dataToDecryptLen, uint8_t *plaintextResponse)
{
    sss_status_t status  = kStatus_SSS_Fail;
    sss_symmetric_t symm = {0};

    uint8_t iv[NX_SYMM_AUTH_INITIAL_VECTOR_SIZE] = NX_SYMM_AUTH_INITIAL_VECTOR;
    uint8_t *pIv                                 = (uint8_t *)iv;

    ENSURE_OR_GO_EXIT(NULL != appKey);
    ENSURE_OR_GO_EXIT(NULL != appKey->keyStore);

    status = sss_host_symmetric_context_init(
        &symm, appKey->keyStore->session, appKey, kAlgorithm_SSS_AES_CBC, kMode_SSS_Decrypt);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_cipher_one_go(
        &symm, pIv, NX_SYMM_AUTH_INITIAL_VECTOR_SIZE, dataToDecrypt, plaintextResponse, dataToDecryptLen);

exit:
    if (symm.session != NULL) {
        sss_host_symmetric_context_free(&symm);
    }
    return status;
}

static sss_status_t host_symmetric_encrypt(
    sss_object_t *appKey, uint8_t *dataToEncrypt, size_t dataToEncryptLen, uint8_t *encCmdData)
{
    sss_status_t status  = kStatus_SSS_Fail;
    sss_symmetric_t symm = {0};

    uint8_t iv[NX_SYMM_AUTH_INITIAL_VECTOR_SIZE] = NX_SYMM_AUTH_INITIAL_VECTOR;
    uint8_t *pIv                                 = (uint8_t *)iv;

    ENSURE_OR_GO_EXIT(NULL != appKey);
    ENSURE_OR_GO_EXIT(NULL != appKey->keyStore);

    status = sss_host_symmetric_context_init(
        &symm, appKey->keyStore->session, appKey, kAlgorithm_SSS_AES_CBC, kMode_SSS_Encrypt);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_cipher_one_go(
        &symm, pIv, NX_SYMM_AUTH_INITIAL_VECTOR_SIZE, dataToEncrypt, encCmdData, dataToEncryptLen);

exit:
    if (symm.session != NULL) {
        sss_host_symmetric_context_free(&symm);
    }
    return status;
}

static sss_status_t host_generate_random(sss_session_t *pSession, uint8_t *rndBuf, size_t rndBufLen)
{
    sss_status_t status      = kStatus_SSS_Fail;
    sss_rng_context_t rngctx = {0};

    ENSURE_OR_GO_EXIT(pSession != NULL);

    status = sss_host_rng_context_init(&rngctx, pSession);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_rng_get_random(&rngctx, rndBuf, rndBufLen);

exit:
    if (rngctx.session != NULL) {
        sss_host_symmetric_context_free(&rngctx);
    }
    return status;
}

static sss_status_t host_do_mac(
    sss_object_t *appKey, uint8_t *dataToMAC, size_t dataToMACLen, uint8_t *macToAdd, size_t macLen)
{
    sss_status_t status       = kStatus_SSS_Fail;
    sss_algorithm_t algorithm = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode           = kMode_SSS_Mac;
    sss_mac_t macCtx          = {0};

    ENSURE_OR_GO_EXIT(NULL != appKey);
    ENSURE_OR_GO_EXIT(NULL != appKey->keyStore);

    status = sss_host_mac_context_init(&macCtx, appKey->keyStore->session, appKey, algorithm, mode);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_host_mac_one_go(&macCtx, dataToMAC, dataToMACLen, macToAdd, &macLen);

exit:
    if (macCtx.session != NULL) {
        sss_host_mac_context_free(&macCtx);
    }
    return status;
}

static smStatus_t convert_RndDash_To_RndBuffer(
    uint8_t *rndDash, size_t rndDashLen, uint8_t *rndBuffer, size_t *rndBufferLen)
{
    smStatus_t retStatus = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != rndDash)
    ENSURE_OR_GO_EXIT(NULL != rndBuffer)
    ENSURE_OR_GO_EXIT(NULL != rndBufferLen)

    if (rndDashLen == NX_SYMM_AUTH_RANDOM_LEN) {
        ENSURE_OR_GO_EXIT((1) <= *rndBufferLen);
        memcpy(rndBuffer, rndDash + 15, 1);
        ENSURE_OR_GO_EXIT((1 + 15) <= *rndBufferLen);
        memcpy(rndBuffer + 1, rndDash, 15);
        *rndBufferLen = rndDashLen;
        retStatus     = SM_OK;
    }

exit:
    return retStatus;
}

static smStatus_t convert_RndBuffer_To_RndDash(
    uint8_t *rndBuffer, size_t rndBufferLen, uint8_t *rndDash, size_t *rndDashLen)
{
    smStatus_t retStatus = SM_NOT_OK;

    ENSURE_OR_GO_EXIT(NULL != rndBuffer)
    ENSURE_OR_GO_EXIT(NULL != rndDash)
    ENSURE_OR_GO_EXIT(NULL != rndDashLen)

    if (rndBufferLen == NX_SYMM_AUTH_RANDOM_LEN) {
        ENSURE_OR_GO_EXIT((15) <= *rndDashLen);
        memcpy(rndDash, rndBuffer + 1, 15);
        ENSURE_OR_GO_EXIT((15 + 1) <= *rndDashLen);
        memcpy(rndDash + 15, rndBuffer, 1);
        *rndDashLen = rndBufferLen;
        retStatus   = SM_OK;
    }

exit:
    return retStatus;
}

static sss_status_t nx_Tx_AuthenticateEV2First_Part1(
    pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndBBuf, size_t RndBDashBufLen)
{
    sss_status_t status  = kStatus_SSS_Fail;
    smStatus_t retStatus = SM_NOT_OK;
    tlvHeader_t hdr      = {{NX_CLA, NX_INS_AUTHENTICATE_EV2_FIRST, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD_HEADER]          = {0};
    size_t cmdHeaderBufLen                                    = 0;
    int tlvRet                                                = 1;
    uint8_t *pCmdHeaderBuf                                    = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]                       = {0};
    uint8_t *pRspbuf                                          = &rspbuf[0];
    size_t rspbufLen                                          = sizeof(rspbuf);
    uint8_t *afRsp                                            = NULL; // Point to additional frame response buffer
    size_t afRspLen                                           = 0;
    uint8_t dataToDecrypt[NX_MAX_BUF_SIZE_CMD]                = {0};
    size_t dataToDecryptLen                                   = 0;
    uint8_t plaintextResponse[NX_AUTH_EV2FIRST_PLAINRSP_SIZE] = {0};
    sss_object_t *appKey                                      = NULL;
    uint8_t *PCDCap2                                          = NULL;
    uint8_t PCDCap2Len                                        = 0;
    uint8_t keyNo                                             = 0;

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);

    appKey     = &pAuthCtx->static_ctx.appKey;
    keyNo      = pAuthCtx->dyn_ctx.keyNo;
    PCDCap2    = pAuthCtx->static_ctx.PCDCap2;
    PCDCap2Len = pAuthCtx->static_ctx.PCDCap2Len;

    tlvRet = SET_U8("KeyNo", &pCmdHeaderBuf, &cmdHeaderBufLen, keyNo, NX_MAX_BUF_SIZE_CMD_HEADER);
    ENSURE_OR_GO_EXIT(0 == tlvRet)

    tlvRet = SET_U8("pcdCap2Len", &pCmdHeaderBuf, &cmdHeaderBufLen, PCDCap2Len, NX_MAX_BUF_SIZE_CMD_HEADER);
    ENSURE_OR_GO_EXIT(0 == tlvRet)

    if ((PCDCap2Len > 0) && (PCDCap2Len <= NX_PCD_CAPABILITIES_LEN)) {
        tlvRet =
            SET_u8buf("PCDCap2", &pCmdHeaderBuf, &cmdHeaderBufLen, PCDCap2, PCDCap2Len, NX_MAX_BUF_SIZE_CMD_HEADER);
        ENSURE_OR_GO_EXIT(0 == tlvRet)
    }
    // AuthenticateEV2Frist Part1
    retStatus = DoAPDUTxRx_s_Case4(seSession, &hdr, cmdHeaderBuf, cmdHeaderBufLen, NULL, 0, rspbuf, &rspbufLen, NULL);
    ENSURE_OR_GO_EXIT(SM_OK == retStatus)

    ENSURE_OR_GO_EXIT(rspbufLen == (NX_SYMM_AUTH_EV2_FIRST_PART1_RESP_LEN + 2))

    // Process additional frame response
    afRsp    = rspbuf;
    afRspLen = rspbufLen;

    if (afRsp[afRspLen - 1] == 0xAF) {
        dataToDecryptLen = afRspLen - 2;
        size_t rspIndex  = 0;
        tlvRet           = get_u8buf(pRspbuf, &rspIndex, rspbufLen, dataToDecrypt, dataToDecryptLen); /*  */
        ENSURE_OR_GO_EXIT(0 == tlvRet)

        status = host_symmetric_decrypt(appKey, dataToDecrypt, dataToDecryptLen, plaintextResponse);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        memcpy(RndBBuf, plaintextResponse, RndBDashBufLen);
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("Invalid additional Frame Rsp");
        goto exit;
    }

exit:
    return status;
}

static sss_status_t nx_Tx_AuthenticateEV2First_Part2(
    pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndBBuf, size_t RndBBufLen)
{
    sss_status_t status                                       = kStatus_SSS_Fail;
    smStatus_t retStatus                                      = SM_NOT_OK;
    int tlvRet                                                = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD]                   = {0};
    uint8_t *pCmdDataBuf                                      = &cmdDataBuf[0];
    size_t cmdDataBufLen                                      = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP]                       = {0};
    uint8_t *pRspbuf                                          = &rspbuf[0];
    size_t rspbufLen                                          = sizeof(rspbuf);
    uint8_t RndABuf[NX_SYMM_AUTH_RANDOM_LEN]                  = {0};
    size_t RndABufLen                                         = sizeof(RndABuf);
    uint8_t resp_RndA[NX_SYMM_AUTH_RANDOM_LEN]                = {0};
    size_t resp_RndALen                                       = sizeof(resp_RndA);
    uint8_t RndADashBuf[NX_SYMM_AUTH_RANDOM_LEN]              = {0};
    size_t RndADashBufLen                                     = sizeof(RndADashBuf);
    uint8_t RndBDashBuf[NX_SYMM_AUTH_RANDOM_LEN]              = {0};
    size_t RndBDashBufLen                                     = sizeof(RndBDashBuf);
    uint8_t dataToEncrypt[NX_AUTH_EV2FIRST_ENCRYPT_BUF_SIZE]  = {0};
    size_t dataToEncryptLen                                   = 0;
    uint8_t encCmdData[NX_AUTH_EV2FIRST_ENCRYPT_BUF_SIZE]     = {0};
    uint8_t dataToDecrypt[NX_AUTH_EV2FIRST_DECRYPT_BUF_SIZE]  = {0};
    size_t dataToDecryptLen                                   = 0;
    uint8_t plaintextResponse[NX_AUTH_EV2FIRST_PLAINRSP_SIZE] = {0};
    sss_session_t *pSession                                   = NULL;
    sss_object_t *appKey                                      = NULL;
    tlvHeader_t hdr = {{NX_CLA, NX_INS_ADDITIONAL_FRAME_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);

    retStatus = convert_RndBuffer_To_RndDash(RndBBuf, RndBBufLen, RndBDashBuf, &RndBDashBufLen);
    if (retStatus != SM_OK) {
        LOG_E("convert_RndBuffer_To_RndDash Failed");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    pSession = pAuthCtx->static_ctx.appKey.keyStore->session;
    appKey   = &pAuthCtx->static_ctx.appKey;

    status = host_generate_random(pSession, RndABuf, RndABufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D("generate RndA", RndABuf, RndABufLen);

    memcpy(dataToEncrypt, RndABuf, RndABufLen);
    ENSURE_OR_GO_EXIT(RndBDashBufLen + RndABufLen <= NX_AUTH_EV2FIRST_DECRYPT_BUF_SIZE);
    memcpy(dataToEncrypt + RndABufLen, RndBDashBuf, RndBDashBufLen);
    dataToEncryptLen = RndABufLen + RndBDashBufLen;

    status = host_symmetric_encrypt(appKey, dataToEncrypt, dataToEncryptLen, encCmdData);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // AuthenticateEV2Frist Part2
    tlvRet = SET_u8buf(
        "Enc RndA||RndBdash", &pCmdDataBuf, &cmdDataBufLen, encCmdData, RndABufLen + RndABufLen, NX_MAX_BUF_SIZE_CMD);
    if (0 != tlvRet) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    retStatus = DoAPDUTxRx_s_Case4(seSession, &hdr, NULL, 0, cmdDataBuf, cmdDataBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != NX_SYMM_AUTH_EV2_FIRST_PART2_RESP_LEN + 2) {
            status = kStatus_SSS_Fail;
            goto exit;
        }

        size_t rspIndex  = 0;
        dataToDecryptLen = (rspbufLen - 2);
        tlvRet           = get_u8buf(pRspbuf, &rspIndex, rspbufLen, dataToDecrypt, (rspbufLen - 2));
        if (0 != tlvRet) {
            status = kStatus_SSS_Fail;
            goto exit;
        }

        retStatus = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
        if (retStatus != SM_OK_ALT) {
            status = kStatus_SSS_Fail;
            goto exit;
        }
    }
    else {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    status = host_symmetric_decrypt(appKey, dataToDecrypt, dataToDecryptLen, plaintextResponse);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    pAuthCtx->dyn_ctx.TI = plaintextResponse[3] << 24;
    pAuthCtx->dyn_ctx.TI |= plaintextResponse[2] << 16;
    pAuthCtx->dyn_ctx.TI |= plaintextResponse[1] << 8;
    pAuthCtx->dyn_ctx.TI |= plaintextResponse[0];

    // RndA'
    memcpy(RndADashBuf, plaintextResponse + NX_SYMM_AUTH_RNDA_DASH_RESP_OFFSET, RndADashBufLen);

    retStatus = convert_RndDash_To_RndBuffer(RndADashBuf, RndADashBufLen, resp_RndA, &resp_RndALen);
    if (retStatus != SM_OK) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    // Update PD capabilities to reader
    memcpy(pAuthCtx->dyn_ctx.PDCap2, plaintextResponse + NX_SYMM_AUTH_PDCAP2_RESP_OFFSET, NX_PD_CAPABILITIES_LEN);
    // Compare PCD capabilities reader with card
    if (0 != memcmp(pAuthCtx->static_ctx.PCDCap2,
                 plaintextResponse + NX_SYMM_AUTH_PCDCAP2_RESP_OFFSET,
                 NX_PCD_CAPABILITIES_LEN)) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    if (0 != memcmp(resp_RndA, RndABuf, NX_SYMM_AUTH_RANDOM_LEN)) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    if (pAuthCtx->static_ctx.appKeySize == NX_SYMM_AUTH_AES128_KEY_SIZE) {
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) || \
    defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        status = symm_auth_derive_AES128_session_keys(pAuthCtx, RndABuf, RndBBuf);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2
    }
    else if (pAuthCtx->static_ctx.appKeySize == NX_SYMM_AUTH_AES256_KEY_SIZE) {
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) || \
    defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        status = symm_auth_derive_AES256_session_keys(pAuthCtx, RndABuf, RndBBuf);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2
    }
    else {
        status = kStatus_SSS_Fail;
        goto exit;
    }

exit:
    return status;
}

static sss_status_t nx_Tx_AuthenticateEV2NonFirst_Part1(
    pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndBBuf, size_t RndBDashBufLen)
{
    sss_status_t status  = kStatus_SSS_Fail;
    smStatus_t retStatus = SM_NOT_OK;

    tlvHeader_t hdr = {{NX_CLA, NX_INS_AUTHENTICATE_EV2_NON_FIRST, NX_P1_DEFAULT, NX_P2_DEFAULT}};
    uint8_t cmdHeaderBuf[NX_MAX_BUF_SIZE_CMD_HEADER] = {0};
    size_t cmdHeaderBufLen                           = 0;
    int tlvRet                                       = 0;
    uint8_t *pCmdHeaderBuf                           = &cmdHeaderBuf[0];
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf = &rspbuf[0];
    size_t rspbufLen = sizeof(rspbuf);
    uint8_t *afRsp   = NULL; // Point to additional frame response buffer
    size_t afRspLen  = 0;

    uint8_t dataToDecrypt[NX_MAX_BUF_SIZE_CMD]                = {0};
    size_t dataToDecryptLen                                   = 0;
    uint8_t plaintextResponse[NX_AUTH_EV2FIRST_PLAINRSP_SIZE] = {0};

    sss_object_t *appKey = NULL;
    uint8_t keyNo        = 0;

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);

    appKey = &pAuthCtx->static_ctx.appKey;

    keyNo  = pAuthCtx->dyn_ctx.keyNo;
    tlvRet = SET_U8("KeyNo", &pCmdHeaderBuf, &cmdHeaderBufLen, keyNo, NX_MAX_BUF_SIZE_CMD_HEADER);
    if (0 != tlvRet) {
        goto exit;
    }
    // AuthenticateEV2Frist Part1
    retStatus = DoAPDUTxRx_s_Case4(seSession, &hdr, cmdHeaderBuf, cmdHeaderBufLen, NULL, 0, rspbuf, &rspbufLen, NULL);
    if (retStatus != SM_OK) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    if (rspbufLen != (NX_SYMM_AUTH_EV2_NON_FIRST_RESP_LEN + 2)) {
        status = kStatus_SSS_Fail;
        goto exit;
    }
    // Process additional frame response
    afRsp    = rspbuf;
    afRspLen = rspbufLen;
    if (afRsp[afRspLen - 1] == 0xAF) {
        dataToDecryptLen = afRspLen - 2;
        size_t rspIndex  = 0;
        tlvRet           = get_u8buf(pRspbuf, &rspIndex, rspbufLen, dataToDecrypt, dataToDecryptLen); /*  */
        if (0 != tlvRet) {
            goto exit;
        }

        status = host_symmetric_decrypt(appKey, dataToDecrypt, dataToDecryptLen, plaintextResponse);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        memcpy(RndBBuf, plaintextResponse, RndBDashBufLen);
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("Invalid additional Frame Rsp");
        goto exit;
    }

exit:
    return status;
}

static sss_status_t nx_Tx_AuthenticateEV2NonFirst_Part2(
    pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx, uint8_t *RndBBuf, size_t RndBBufLen)
{
    sss_status_t status                     = kStatus_SSS_Fail;
    smStatus_t retStatus                    = SM_NOT_OK;
    int tlvRet                              = 0;
    uint8_t cmdDataBuf[NX_MAX_BUF_SIZE_CMD] = {0};
    uint8_t *pCmdDataBuf                    = &cmdDataBuf[0];
    size_t cmdDataBufLen                    = 0;
    uint8_t rspbuf[NX_MAX_BUF_SIZE_RSP];
    uint8_t *pRspbuf                                          = &rspbuf[0];
    size_t rspbufLen                                          = sizeof(rspbuf);
    uint8_t RndABuf[NX_SYMM_AUTH_RANDOM_LEN]                  = {0};
    size_t RndABufLen                                         = sizeof(RndABuf);
    uint8_t resp_RndA[NX_SYMM_AUTH_RANDOM_LEN]                = {0};
    size_t resp_RndALen                                       = sizeof(resp_RndA);
    uint8_t RndADashBuf[NX_SYMM_AUTH_RANDOM_LEN]              = {0};
    size_t RndADashBufLen                                     = sizeof(RndADashBuf);
    uint8_t RndBDashBuf[NX_SYMM_AUTH_RANDOM_LEN]              = {0};
    size_t RndBDashBufLen                                     = sizeof(RndBDashBuf);
    uint8_t dataToEncrypt[NX_AUTH_EV2FIRST_ENCRYPT_BUF_SIZE]  = {0};
    size_t dataToEncryptLen                                   = 0;
    uint8_t encCmdData[NX_AUTH_EV2FIRST_ENCRYPT_BUF_SIZE]     = {0};
    uint8_t dataToDecrypt[NX_AUTH_EV2FIRST_DECRYPT_BUF_SIZE]  = {0};
    size_t dataToDecryptLen                                   = 0;
    uint8_t plaintextResponse[NX_AUTH_EV2FIRST_PLAINRSP_SIZE] = {0};
    sss_session_t *pSession                                   = NULL;
    sss_object_t *appKey                                      = NULL;
    tlvHeader_t hdr = {{NX_CLA, NX_INS_ADDITIONAL_FRAME_REQ, NX_P1_DEFAULT, NX_P2_DEFAULT}};

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);

    retStatus = convert_RndBuffer_To_RndDash(RndBBuf, RndBBufLen, RndBDashBuf, &RndBDashBufLen);
    if (retStatus != SM_OK) {
        LOG_E("convert_RndBuffer_To_RndDash Failed");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    pSession = pAuthCtx->static_ctx.appKey.keyStore->session;
    appKey   = &pAuthCtx->static_ctx.appKey;

    status = host_generate_random(pSession, RndABuf, RndABufLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    LOG_MAU8_D("generate RndA", RndABuf, RndABufLen);

    memcpy(dataToEncrypt, RndABuf, RndABufLen);
    ENSURE_OR_GO_EXIT(RndBDashBufLen + RndABufLen <= NX_AUTH_EV2FIRST_DECRYPT_BUF_SIZE);
    memcpy(dataToEncrypt + RndABufLen, RndBDashBuf, RndBDashBufLen);
    dataToEncryptLen = RndABufLen + RndBDashBufLen;

    status = host_symmetric_encrypt(appKey, dataToEncrypt, dataToEncryptLen, encCmdData);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // AuthenticateEV2Frist Part2
    tlvRet = SET_u8buf(
        "Enc RndA||RndBdash", &pCmdDataBuf, &cmdDataBufLen, encCmdData, RndABufLen + RndABufLen, NX_MAX_BUF_SIZE_CMD);
    if (0 != tlvRet) {
        goto exit;
    }

    retStatus = DoAPDUTxRx_s_Case4(seSession, &hdr, NULL, 0, cmdDataBuf, cmdDataBufLen, rspbuf, &rspbufLen, NULL);
    if (retStatus == SM_OK) {
        retStatus = SM_NOT_OK;
        if (rspbufLen != NX_SYMM_AUTH_EV2_NON_FIRST_RESP_LEN + 2) {
            status = kStatus_SSS_Fail;
            goto exit;
        }
        size_t rspIndex  = 0;
        dataToDecryptLen = (rspbufLen - 2);
        tlvRet           = get_u8buf(pRspbuf, &rspIndex, rspbufLen, dataToDecrypt, (rspbufLen - 2));
        if (0 != tlvRet) {
            goto exit;
        }
        retStatus = (pRspbuf[rspbufLen - 2] << 8) | (pRspbuf[rspbufLen - 1]);
        if (retStatus != SM_OK_ALT) {
            status = kStatus_SSS_Fail;
            goto exit;
        }
    }

    status = host_symmetric_decrypt(appKey, dataToDecrypt, dataToDecryptLen, plaintextResponse);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // RndA'
    memcpy(RndADashBuf, plaintextResponse, RndADashBufLen);

    retStatus = convert_RndDash_To_RndBuffer(RndADashBuf, RndADashBufLen, resp_RndA, &resp_RndALen);
    if (retStatus != SM_OK) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    if (0 != memcmp(resp_RndA, RndABuf, NX_SYMM_AUTH_RANDOM_LEN)) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    if (pAuthCtx->static_ctx.appKeySize == NX_SYMM_AUTH_AES128_KEY_SIZE) {
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2) || \
    defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        status = symm_auth_derive_AES128_session_keys(pAuthCtx, RndABuf, RndBBuf);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES128_EV2
    }
    else if (pAuthCtx->static_ctx.appKeySize == NX_SYMM_AUTH_AES256_KEY_SIZE) {
#if defined(SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) && (SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2) || \
    defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        status = symm_auth_derive_AES256_session_keys(pAuthCtx, RndABuf, RndBBuf);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
#endif // SSS_HAVE_SECURE_TUNNELING_NTAG_AES256_EV2
    }
    else {
        status = kStatus_SSS_Fail;
        goto exit;
    }

exit:
    return status;
}
/**
 * @brief         Construct host random C-APDU.
 *                Tx C-APDU.
 *
 *                C-APDU: 83 10 <Host's random, 16 bytes>
 *                R-APDU:
 *                  83 10 <DA OS's random, 16 bytes>
 *                  84 20 <cert hash, 32 bytes>
 *                  85 40 <signature, 64 bytes>
 *
 * @param         seSession          SE session
 * @param         pAuthCtx              Context Pointer to auth context.
 *
 * @return        Status.
 */
sss_status_t nx_symm_authenticate_channel(pSeSession_t seSession, nx_auth_symm_ctx_t *pAuthCtx)
{
    sss_status_t status                      = kStatus_SSS_Fail;
    uint8_t RndBBuf[NX_SYMM_AUTH_RANDOM_LEN] = {0};
    size_t RndBBufLen                        = sizeof(RndBBuf);

    ENSURE_OR_GO_EXIT(seSession != NULL);
    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);

    if (pAuthCtx->dyn_ctx.authStatus == kVCState_NotAuthenticated) {
        status = nx_Tx_AuthenticateEV2First_Part1(seSession, pAuthCtx, RndBBuf, RndBBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        pAuthCtx->dyn_ctx.authStatus = kVCState_PartiallyAuthenticated;

        status = nx_Tx_AuthenticateEV2First_Part2(seSession, pAuthCtx, RndBBuf, RndBBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        pAuthCtx->dyn_ctx.authStatus = kVCState_AuthenticatedAES;
    }
    else if (pAuthCtx->dyn_ctx.authStatus == kVCState_AuthenticatedAES) {
        status = nx_Tx_AuthenticateEV2NonFirst_Part1(seSession, pAuthCtx, RndBBuf, RndBBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        pAuthCtx->dyn_ctx.authStatus = kVCState_PartiallyAuthenticated;

        status = nx_Tx_AuthenticateEV2NonFirst_Part2(seSession, pAuthCtx, RndBBuf, RndBBufLen);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
        pAuthCtx->dyn_ctx.authStatus = kVCState_AuthenticatedAES;
    }
    else {
        LOG_E("Invalid AuthStatus");
    }

exit:
    return status;
}
#endif // SSS_HAVE_AUTH_SYMM_AUTH

#if (defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
    (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)) ||     \
    (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH)) ||               \
    (defined(SSS_HAVE_ALL_AUTH_CODE_ENABLED) && (SSS_HAVE_ALL_AUTH_CODE_ENABLED))
sss_status_t nx_prepare_host_for_auth(
    sss_session_t *host_session, sss_key_store_t *host_ks, nx_connect_ctx_t *nx_conn_ctx)
{
    sss_status_t status      = kStatus_SSS_Fail;
    nx_auth_type_t auth_type = knx_AuthType_None;

    ENSURE_OR_GO_CLEANUP(NULL != host_session);
    ENSURE_OR_GO_CLEANUP(NULL != nx_conn_ctx);

    if (host_session->subsystem == kType_SSS_SubSystem_NONE) {
        // No host crypto session found. Open a session.
        sss_type_t hostsubsystem = kType_SSS_SubSystem_NONE;

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
        hostsubsystem = kType_SSS_mbedTLS;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
        hostsubsystem = kType_SSS_OpenSSL;
#elif
        LOG_E("No host crypto selected in build system.");
        goto cleanup;
#endif
        status = sss_host_session_open(host_session, hostsubsystem, 0, kSSS_ConnectionType_Plain, NULL);

        if (kStatus_SSS_Success != status) {
            LOG_E("Failed to open Host Session");
            goto cleanup;
        }
        status = sss_host_key_store_context_init(host_ks, host_session);
        if (kStatus_SSS_Success != status) {
            LOG_E("Host: sss_key_store_context_init failed");
            goto cleanup;
        }
        status = sss_host_key_store_allocate(host_ks, __LINE__);
        if (kStatus_SSS_Success != status) {
            LOG_E("Host: sss_key_store_allocate failed");
            goto cleanup;
        }
    }

    auth_type = nx_conn_ctx->auth.authType;

    if (auth_type == knx_AuthType_SIGMA_I_Verifier || auth_type == knx_AuthType_SIGMA_I_Prover) {
#if SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER || SSS_HAVE_ALL_AUTH_CODE_ENABLED
        sss_cipher_type_t host_cert_curve_type  = kSSS_CipherType_NONE;
        sss_cipher_type_t host_ephem_curve_type = kSSS_CipherType_NONE;
        host_cert_curve_type                    = nx_conn_ctx->auth.ctx.sigmai.static_ctx.hostCertCurveType;
        host_ephem_curve_type                   = nx_conn_ctx->auth.ctx.sigmai.dyn_ctx.hostEphemCurveType;

        status = nx_prepare_host_for_auth_key_sigma_i(
            &nx_conn_ctx->auth.ctx.sigmai, host_ks, host_cert_curve_type, host_ephem_curve_type);
        if (kStatus_SSS_Success != status) {
            LOG_E("Host: nx_prepare_host_for_auth_key_sigma_i failed");
            goto cleanup;
        }

        nx_conn_ctx->auth.ctx.sigmai.static_ctx.fp_find_hash_from_cache        = EX_SSS_CACHE_FUNC_FIND_HASH;
        nx_conn_ctx->auth.ctx.sigmai.static_ctx.fp_get_pk_from_cache           = EX_SSS_CACHE_FUNC_GET_PUBLIC_KEY;
        nx_conn_ctx->auth.ctx.sigmai.static_ctx.fp_insert_hash_pk_to_cache     = EX_SSS_CACHE_FUNC_INSERT_HASH_PK;
        nx_conn_ctx->auth.ctx.sigmai.static_ctx.fp_get_parent_cert_from_cache  = EX_SSS_CACHE_FUNC_GET_PARENT_CERT;
        nx_conn_ctx->auth.ctx.sigmai.static_ctx.fp_insert_parent_cert_to_cache = EX_SSS_CACHE_FUNC_INSET_PUBLIC_KEY;
#else
        LOG_E("Wrong Authentication option selected. Rebuild the library with correct AUTH option");
        goto cleanup;
#endif // SSS_HAVE_AUTH_SIGMA_I_VERIFIER || SSS_HAVE_AUTH_SIGMA_I_PROVER || SSS_HAVE_ALL_AUTH_CODE_ENABLED
    }
    else if (auth_type == knx_AuthType_SYMM_AUTH) {
#if SSS_HAVE_AUTH_SYMM_AUTH || SSS_HAVE_ALL_AUTH_CODE_ENABLED
        status = nx_prepare_host_for_auth_key_symm_auth(&nx_conn_ctx->auth.ctx.symmAuth, host_ks, nx_conn_ctx);
        if (kStatus_SSS_Success != status) {
            LOG_E("Host: nx_prepare_host_for_auth_key_symm_auth failed");
            goto cleanup;
        }

        nx_conn_ctx->auth.ctx.symmAuth.dyn_ctx.authType = auth_type;
#else
        LOG_E("Wrong Authentication option selected. Rebuild the library with correct AUTH option");
        goto cleanup;
#endif // SSS_HAVE_AUTH_SYMM_AUTH
    }
    else if (auth_type == knx_AuthType_None) {
        status = kStatus_SSS_Fail;
        LOG_E("Cannot set auth_type to None for an authenticated session");
    }
    else {
        status = kStatus_SSS_Fail;
        LOG_E("Invalid auth type");
    }

cleanup:
    return status;
}
#endif // Any one of the Tunneling Mechanisms

#endif // SSS_HAVE_NX_TYPE
