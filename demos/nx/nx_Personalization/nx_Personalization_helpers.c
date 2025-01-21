/*
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>
#include "nxEnsure.h"
#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "fsl_sss_nx_auth_types.h"
#include "nxLog_msg.h"
#include "fsl_sss_util_asn1_der.h"

#if SSS_HAVE_NX_TYPE

static sss_status_t sss_nx_get_cert_value_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen);
static sss_status_t sss_nx_get_cert_tlv_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen);

sss_status_t sss_nx_provision_import_se_leaf_private_key(ex_sss_boot_ctx_t *pCtx,
    uint8_t seLeafCertKeyId,
    Nx_ECCurve_t seCertCurveType,
    uint8_t *seLeafPKBuf,
    size_t seLeafPKBufLen)
{
    sss_status_t status                = kStatus_SSS_Fail;
    const sss_policy_u eccKeyGenPolicy = {.type = KPolicy_GenECKey,
        .policy                                 = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .sigmaiEnabled         = 1,
                       .eccSignEnabled        = 0,
                       .ecdhEnabled           = 0,
                       .writeCommMode         = kCommMode_FULL,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x0,
                       .kucLimit              = 0,
                       .userCommMode          = Nx_CommMode_NA,
                   }}};
    sss_policy_t ec_key_policy         = {.nPolicies = 1, .policies = {&eccKeyGenPolicy}};
    sss_object_t keyObject             = {0};
    sss_cipher_type_t cipherType       = kSSS_CipherType_NONE;

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    ENSURE_OR_GO_EXIT(seLeafPKBuf != NULL);

    ENSURE_OR_GO_EXIT((seCertCurveType == Nx_ECCurve_Brainpool256) || (seCertCurveType == Nx_ECCurve_NIST_P256));

    if (seCertCurveType == Nx_ECCurve_Brainpool256) {
        cipherType = kSSS_CipherType_EC_BRAINPOOL;
    }
    else {
        cipherType = kSSS_CipherType_EC_NIST_P;
    }

    status = sss_key_object_init(&keyObject, &pCtx->ks);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
    status = kStatus_SSS_Fail;

    status = sss_key_object_allocate_handle(
        &keyObject, seLeafCertKeyId, kSSS_KeyPart_Private, cipherType, 256 / 8, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
    status = kStatus_SSS_Fail;

    status = sss_key_store_set_key(
        &pCtx->ks, &keyObject, seLeafPKBuf, seLeafPKBufLen, 256, &ec_key_policy, sizeof(ec_key_policy));
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = kStatus_SSS_Success;
exit:
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }
    return status;
}

static sss_status_t sss_nx_get_cert_value_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t i            = 0;
    int ret             = 0;
    uint8_t fieldTag = 0, qualifierTag = 0;
    uint8_t *pCert = NULL, *certEnd = NULL;
    size_t len = 0;

    if ((certBuf == NULL) || (asn1TagList == NULL) || (dataBuf == NULL) || (dataBufLen == NULL)) {
        goto exit;
    }

    pCert   = certBuf;
    len     = certBufLen;
    certEnd = pCert + len;

    for (i = 0; (((i + 1) < asn1TagListLen) && (i <= (SIZE_MAX - 2))); i = i + 2) {
        fieldTag     = asn1TagList[i];
        qualifierTag = asn1TagList[i + 1];

        if (fieldTag != 0x00) {
            if ((ret = sss_util_asn1_get_tag(&pCert, certEnd, &len, fieldTag)) != 0) {
                LOG_E("Parse certificate tag 0x%x error", fieldTag);
                goto exit;
            }
        }
        else {
            // 0x00 tag, in fact, is padding for BIT STRING.
            pCert++;
            len = 0;
        }

        if (qualifierTag == NX_Qualifier_Nested) {
            ;
        }
        else if (qualifierTag == NX_Qualifier_Follow) {
            pCert += len;
        }
        else if (qualifierTag == NX_Qualifier_End) {
            // pCert point to value field, len is the value field length.
            break;
        }
        else {
            LOG_E("Invalid Qualifier Tag 0x%x error", qualifierTag);
            goto exit;
        }
    }

    if (qualifierTag != NX_Qualifier_End) {
        LOG_E("No Qualifier End Tag found");
        goto exit;
    }

    // pCert point to value field, len is the value field length.

    *dataBuf    = pCert;
    *dataBufLen = len;

    status = kStatus_SSS_Success;

exit:
    return status;
}

static sss_status_t sss_nx_get_cert_tlv_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t i            = 0;
    int ret             = 0;
    uint8_t fieldTag = 0, qualifierTag = 0;
    uint8_t *pCert = NULL, *certEnd = NULL, *pTag = NULL;
    size_t len = 0;

    if ((certBuf == NULL) || (asn1TagList == NULL) || (dataBuf == NULL) || (dataBufLen == NULL)) {
        goto exit;
    }

    pCert   = certBuf;
    len     = certBufLen;
    certEnd = pCert + len;

    for (i = 0; (((i + 1) < asn1TagListLen) && (i <= (SIZE_MAX - 2))); i = i + 2) {
        fieldTag     = asn1TagList[i];
        qualifierTag = asn1TagList[i + 1];

        pTag = pCert;

        if (fieldTag != 0x00) {
            if ((ret = sss_util_asn1_get_tag(&pCert, certEnd, &len, fieldTag)) != 0) {
                LOG_E("Parse certificate tag 0x%x error", fieldTag);
                goto exit;
            }
        }
        else {
            // 0x00 tag, in fact, is padding for BIT STRING.
            pCert++;
            len = 0;
        }

        if (qualifierTag == NX_Qualifier_Nested) {
            ;
        }
        else if (qualifierTag == NX_Qualifier_Follow) {
            pCert += len;
        }
        else if (qualifierTag == NX_Qualifier_End) {
            // pCert point to value field, len is the value field length.
            break;
        }
        else {
            LOG_E("Invalid Qualifier Tag 0x%x error", qualifierTag);
            goto exit;
        }
    }

    if (qualifierTag != NX_Qualifier_End) {
        LOG_E("No Qualifier End Tag found");
        goto exit;
    }

    // pTag is start of tag field
    *dataBuf = pTag;
    ENSURE_OR_GO_EXIT((UINT_MAX - (size_t)(pCert - pTag)) >= len);
    *dataBufLen = pCert - pTag + len;

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t sss_nx_provision_load_host_root_CA_pubkey(ex_sss_boot_ctx_t *pCtx,
    Nx_ECCurve_t curveType,
    uint8_t hostRootPubKeyId,
    uint16_t accessRight,
    uint8_t *certBuf,
    size_t certLen,
    uint8_t *pkASN1TagList,
    size_t pkASN1TagListLen,
    uint8_t *subjectNameTagList,
    size_t subjectNameTagListLen)
{
    sss_status_t status          = kStatus_SSS_Fail;
    sss_nx_session_t *pSession   = NULL;
    sss_cipher_type_t cipherType = {0};
    sss_object_t keyObject       = {0};
    sss_policy_u rootKeyPolicy   = {
        .type   = KPolicy_UpdateCARootKey,
        .policy = {.updCARootKey =
                       {
                           .acBitmap        = accessRight,
                           .writeCommMode   = Nx_CommMode_FULL,
                           .writeAccessCond = Nx_AccessCondition_Auth_Required_0x0,
                           .userCommMode    = Nx_CommMode_NA,
                       }},
    };
    sss_policy_t root_key_policy = {.nPolicies = 1, .policies = {&rootKeyPolicy}};
    uint8_t *pubKey = NULL, *issuerName = NULL;
    size_t pubKeyLen = 0, issuerNameLen = 0;

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    ENSURE_OR_GO_EXIT((pkASN1TagList != NULL) && (subjectNameTagList != NULL));
    ENSURE_OR_GO_EXIT((curveType == Nx_ECCurve_Brainpool256) || (curveType == Nx_ECCurve_NIST_P256));

    pSession = (sss_nx_session_t *)&pCtx->session;

    // Get Subject Name from certificate.
    status = sss_nx_get_cert_tlv_field(
        certBuf, certLen, subjectNameTagList, subjectNameTagListLen, &issuerName, &issuerNameLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Get public key from certificate.
    status = sss_nx_get_cert_value_field(certBuf, certLen, pkASN1TagList, pkASN1TagListLen, &pubKey, &pubKeyLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Remove 00 pad at the header
    pubKey++;
    if (pubKeyLen <= 0) {
        status = kStatus_SSS_Fail;
        goto exit;
    }
    pubKeyLen--;

    if (issuerNameLen > UINT8_MAX) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    status = kStatus_SSS_Fail;

    // Update issuer name in policy
    memset(rootKeyPolicy.policy.updCARootKey.issuer, 0, sizeof(rootKeyPolicy.policy.updCARootKey.issuer));
    memcpy(rootKeyPolicy.policy.updCARootKey.issuer, issuerName, issuerNameLen);
    rootKeyPolicy.policy.updCARootKey.issuerLen = issuerNameLen;

    // Update write access condition in policy
    if (pSession->s_ctx.authType == knx_AuthType_SYMM_AUTH) {
        if (pSession->s_ctx.ctx.pdynSymmAuthCtx != NULL) {
            rootKeyPolicy.policy.updCARootKey.writeAccessCond = pSession->s_ctx.ctx.pdynSymmAuthCtx->keyNo;
        }
        else {
            LOG_E("Invalid symm auth context !!!");
            goto exit;
        }
    }

    if (curveType == Nx_ECCurve_Brainpool256) {
        cipherType = kSSS_CipherType_CARootKeys_BRAINPOOL;
    }
    else {
        cipherType = kSSS_CipherType_CARootKeys_NIST_P;
    }

    status = sss_key_object_init(&keyObject, &pCtx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyObject, hostRootPubKeyId, kSSS_KeyPart_Public, cipherType, 256 / 8, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_key_store_set_key(&pCtx->ks, &keyObject, pubKey, pubKeyLen, 256, &root_key_policy, sizeof(root_key_policy));
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = kStatus_SSS_Success;
exit:

    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }
    return status;
}

int nx_perso_util_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint8_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint8_t *prvkeyIndex,
    size_t *privateKeyLen)
{
    size_t i      = 0;
    size_t taglen = 0;
    int tag       = 0;
    int ret       = -1;

    ENSURE_OR_GO_EXIT(input != NULL);
    ENSURE_OR_GO_EXIT(pubkeyIndex != NULL);
    ENSURE_OR_GO_EXIT(publicKeyLen != NULL);
    ENSURE_OR_GO_EXIT(prvkeyIndex != NULL);
    ENSURE_OR_GO_EXIT(privateKeyLen != NULL);

    for (;;) {
        ENSURE_OR_GO_EXIT(i < inLen);
        tag = input[i++];
        if (IS_VALID_TAG(tag)) {
            ENSURE_OR_GO_EXIT(i < inLen);
            taglen = input[i++];
            if (taglen == 0x81) {
                ENSURE_OR_GO_EXIT(i < inLen);
                taglen = input[i];
                i      = i + 1;
            }
            else if (taglen == 0x82) {
                ENSURE_OR_GO_EXIT(i < (inLen - 1));
                taglen = input[i] | input[i + 1] << 8;
                i      = i + 2;
            }

            if (taglen > inLen) {
                goto exit;
            }

            if (tag == ASN_TAG_OCTETSTRING) {
                ENSURE_OR_GO_EXIT((SIZE_MAX - i) >= taglen);
                if (i + taglen == inLen) {
                    continue;
                }
                else {
                    *prvkeyIndex   = (uint8_t)i;
                    *privateKeyLen = taglen;
                }
            }

            if (tag == ASN_TAG_BITSTRING) {
                *pubkeyIndex  = (uint8_t)i;
                *publicKeyLen = taglen;
                ENSURE_OR_GO_EXIT(i < inLen);
                if (input[i] == 0x00 || input[i] == 0x01) {
                    ENSURE_OR_GO_EXIT((UINT8_MAX - 1) >= (*pubkeyIndex));
                    *pubkeyIndex  = *pubkeyIndex + 1;
                    *publicKeyLen = *publicKeyLen - 1;
                }
                break;
            }
            ENSURE_OR_GO_EXIT((SIZE_MAX - i) >= taglen);
            if (i + taglen == inLen) {
                continue;
            }
            else {
                i = i + taglen;
            }
        }
        else {
            goto exit;
        }
    }

    ENSURE_OR_GO_EXIT((*pubkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT((UINT_MAX - (*pubkeyIndex)) >= (*publicKeyLen));
    ENSURE_OR_GO_EXIT(((*pubkeyIndex) + (*publicKeyLen)) <= inLen);
    ENSURE_OR_GO_EXIT((*prvkeyIndex) < inLen);
    ENSURE_OR_GO_EXIT((UINT_MAX - (*prvkeyIndex)) >= (*privateKeyLen));
    ENSURE_OR_GO_EXIT(((*prvkeyIndex) + (*privateKeyLen)) <= inLen);
    ret = 0;

exit:
    return ret;
}
#endif // SSS_HAVE_NX_TYPE
