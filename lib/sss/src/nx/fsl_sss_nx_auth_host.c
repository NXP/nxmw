/*
*
* Copyright 2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

/** @file */
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_ANY

#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include "fsl_sss_nx_auth.h"
#include "fsl_sss_nx_auth_keys.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "fsl_sss_util_asn1_der.h"

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1write.h"
#endif
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

/* *****************************************************************************************************************
* Internal Definitions
* ***************************************************************************************************************** */
#ifndef MAKE_TEST_ID
#define MAKE_TEST_ID(ID) (0xEF000000u + ID)
#endif /* MAKE_TEST_ID */

/* *****************************************************************************************************************
* Hostcrypto functions for various auth operations
* ***************************************************************************************************************** */

/**
 * @brief         Convert curve type from sss_cipher_type_t to hostcrypto specific macros.
 *
 * @param         curveType       Curve type (of an ECC key)
 * @return        Group ID        Hostcrypto specific macro for the curve
 */
int nx_hostcrypto_curve_type_to_group_id(sss_cipher_type_t curveType)
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    int groupId = MBEDTLS_ECP_DP_NONE;

    switch (curveType) {
    case kSSS_CipherType_EC_BRAINPOOL:
        groupId = MBEDTLS_ECP_DP_BP256R1;
        break;
    case kSSS_CipherType_EC_NIST_P:
        groupId = MBEDTLS_ECP_DP_SECP256R1;
        break;
    default:
        break;
        /* Do nothing, groupId shall be returned as MBEDTLS_ECP_DP_NONE */
    }

    return groupId;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    int nid = -1;

    switch (curveType) {
    case kSSS_CipherType_EC_BRAINPOOL:
        nid = NID_brainpoolP256r1;
        break;
    case kSSS_CipherType_EC_NIST_P:
        nid = NID_X9_62_prime256v1;
        break;
    default:
        break; /* Do nothing, nid shall be returned as -1 */
    }

    return nid;
#endif
}

/**
 * @brief         Validate Public Key
 *
 *                This API checks if the public key received from the SE is a valid one,
 *                by ensuring the public key (point) lies on the curve it is expected to.
 *
 * @param         pubKeyBuf          The buffer containing the raw public key
 * @param         pubKeyBufLen       Length of the public key buffer
 * @param         curveType          Curve on which the public key is expected to lie
 * @return        Status of pubkey validation
 */
sss_status_t nx_hostcrypto_validate_pubkey(uint8_t *pubKeyBuf, size_t pubKeyBufLen, sss_cipher_type_t curveType)
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    sss_status_t status = kStatus_SSS_Fail;
    int mbedtlsResult   = 1;

    mbedtls_ecp_point point      = {0};
    mbedtls_ecp_group group      = {0};
    mbedtls_ecp_group_id groupId = MBEDTLS_ECP_DP_NONE;

    /* Get the MbedTLS group ID for the reference curve */
    groupId = nx_hostcrypto_curve_type_to_group_id(curveType);
    if (MBEDTLS_ECP_DP_NONE == groupId) {
        LOG_E("Invalid curve type for public key validation");
        goto exit;
    }

    /* Initialize MbedTLS structures */
    mbedtls_ecp_group_init(&group);

    /* Load the group with domain parameters of reference curve (i.e. groupId) */
    mbedtlsResult = mbedtls_ecp_group_load(&group, groupId);
    ENSURE_OR_GO_EXIT(0 == mbedtlsResult);

    mbedtls_ecp_point_init(&point);

    /* Convert the public key buffer in the MbedTLS point format */
    mbedtlsResult = mbedtls_ecp_point_read_binary(&group, &point, pubKeyBuf, pubKeyBufLen);
    ENSURE_OR_GO_EXIT(0 == mbedtlsResult);

    /* Check if the point lies on the curve */
    mbedtlsResult = mbedtls_ecp_check_pubkey(&group, &point);
    ENSURE_OR_GO_EXIT(0 == mbedtlsResult);

    status = kStatus_SSS_Success;
exit:
    mbedtls_ecp_group_free(&group);
    mbedtls_ecp_point_free(&point);
    return status;

#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    sss_status_t status = kStatus_SSS_Fail;
    int opensslResult   = 0;
    int nid             = -1;
    EC_GROUP *group     = NULL;
    EC_POINT *point     = NULL;

    /* Get the OpenSSL nid for the reference curve */
    nid = nx_hostcrypto_curve_type_to_group_id(curveType);
    if (-1 == nid) {
        LOG_E("Invalid curve type for public key validation");
        goto exit;
    }

    /* Create and initialize the OpenSSL curve from derived nid */
    group = EC_GROUP_new_by_curve_name(nid);
    ENSURE_OR_GO_EXIT(NULL != group);

    /* Create and initialize the group with domain parameters of reference curve (i.e. nid) */
    point = EC_POINT_new(group);
    ENSURE_OR_GO_EXIT(NULL != point);

    /* Convert the public key buffer in the OpenSSL point format */
    opensslResult = EC_POINT_oct2point(group, point, pubKeyBuf, pubKeyBufLen, NULL /*?*/);
    ENSURE_OR_GO_EXIT(1 == opensslResult);

    /* Check if the point lies on the curve */
    opensslResult = EC_POINT_is_on_curve(group, point, NULL);
    ENSURE_OR_GO_EXIT(1 == opensslResult);

    status = kStatus_SSS_Success;
exit:
    if (NULL != group) {
        EC_GROUP_free(group);
    }
    if (NULL != point) {
        EC_POINT_free(point);
    }
    return status;
#endif
}

// Misc callback for MBEDTLS
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
int nx_parse_crt_ext_cb(void *p_ctx,
    mbedtls_x509_crt const *crt,
    mbedtls_x509_buf const *oid,
    int critical,
    const unsigned char *cp,
    const unsigned char *end)
{
    return 0;
}
#endif // SSS_HAVE_HOSTCRYPTO_MBEDTLS

/*
 * @brief         Parse PKCS7/X509 certificate
 *
 *                Parse PKCS7/X509 certificate and store it in X509 container of the respective hostcrypto
 *
 * @param         deviceCertCtx      Context Pointer to device certificate context.
 * @param         certType           Type of certificate- device certificate or CA certificate
 * @param         certIndex          Cert index, i.e. its position in the certificate chain
 * @param         certBuf            Cert buffer.
 * @param         certBufLen         Cert buffer length.
 *
 * @return        Status of searching.
 */
sss_status_t nx_hostcrypto_parse_x509_cert(nx_device_cert_ctx_host_t *deviceCertCtx,
    nx_auth_cert_type_t certType,
    nx_cert_level_t certIndex,
    unsigned char *certBuf,
    size_t certBufLen)
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    int ret                  = -1;
    sss_status_t status      = kStatus_SSS_Fail;
    unsigned char *p         = NULL;
    unsigned char *end       = NULL;
    size_t len               = 0;
    uint8_t pkcs7_data_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
    mbedtls_x509_crt *pCert  = NULL;

    ENSURE_OR_GO_EXIT(deviceCertCtx != NULL);
    ENSURE_OR_GO_EXIT(certBuf != NULL);
    ENSURE_OR_GO_EXIT(certType == kDeviceCert || certType == kDeviceCACert);

    if (certType == kDeviceCert) {
        pCert = &deviceCertCtx->deviceLeafCert;
    }
    else {
        pCert = &deviceCertCtx->deviceCACertList[certIndex];
    }

    // Parse X.509 certificate.
    ret = mbedtls_x509_crt_parse_der_with_ext_cb(
        pCert, (const unsigned char *)certBuf, certBufLen, 0, nx_parse_crt_ext_cb, NULL);
    if (ret != 0) {
        // PKCS#7 certificate. Not X.509 certificate.
        LOG_D("mbedtls parse certificates failed. This maybe a PKCS#7 certificate");

        p   = certBuf;
        len = certBufLen;
        end = p + len;

        // SEQ
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            LOG_E("PKCS7 CERT SEQ error");
            goto exit;
        }

        // Get obj id, 0x2A864886F70D010702, 1.2.840.113549.1.7.2 signedData (PKCS #7)
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OID)) != 0) {
            LOG_E("Get PKCS7 CERT 1.2.840.113549.1.7.2(signedData) failed");
            goto exit;
        }

        if ((len != sizeof(pkcs7_data_oid)) || (memcmp(p, &pkcs7_data_oid[0], len) != 0)) {
            LOG_E("PKCS7 CERT obj id is not 1.2.840.113549.1.7.2(signedData)");
            goto exit;
        }

        // Get Tag 0(content)
        p = p + len;
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) !=
            0) {
            LOG_E("Get PKCS7 CERT Tag 0(content) failed");
            goto exit;
        }

        // Get SEQ(SignedData)
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            LOG_E("Get PKCS7 CERT SEQ (SignedData) failed");
            goto exit;
        }

        // Get INTEGER(version)
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
            LOG_E("Get PKCS7 CERT SEQ (SignedData) failed");
            goto exit;
        }

        // Get SET(digestAlgorithms)
        p = p + len;
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET)) != 0) {
            LOG_E("Get PKCS7 CERT SET (SignedData) failed");
            goto exit;
        }

        // Get SEQ(contentInfo)
        p = p + len;
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) != 0) {
            LOG_E("Get PKCS7 CERT SEQ (contentInfo) failed");
            goto exit;
        }

        // Get Tag 0(certificates)
        p = p + len;
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED)) !=
            0) {
            LOG_E("Get PKCS7 CERT Tag 0 (certificates) failed");
            goto exit;
        }

        // Parse X.509 certificate.
        ret =
            mbedtls_x509_crt_parse_der_with_ext_cb(pCert, (const unsigned char *)p, len, 0, nx_parse_crt_ext_cb, NULL);
        if (ret != 0) {
            LOG_E("mbedtls parse certificates failed %d", ret);
            goto exit;
        }
    }

    status = kStatus_SSS_Success;

exit:
    return status;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    int ret = -1;
    sss_status_t status = kStatus_SSS_Fail;
    unsigned char *p = NULL, *end = NULL;
    size_t len = 0;
    uint8_t pkcs7_data_oid[] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
    X509 *x509 = NULL;

    ENSURE_OR_GO_EXIT(certBuf != NULL);

    const unsigned char *certBufPtr = certBuf;
    if (certBufLen > INT_MAX) {
        status = kStatus_SSS_Fail;
        goto exit;
    }
    x509 = d2i_X509(NULL, &certBufPtr, (int)certBufLen);

    // Parse X.509 certificate.
    if (x509 == NULL) {
        // PKCS#7 certificate. Not X.509 certificate.
        LOG_D("Parse certificates failed. This maybe a PKCS#7 certificate");

        p = certBuf;
        len = certBufLen;
        end = p + len;

        // SEQ
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
            LOG_E("PKCS7 CERT SEQ error");
            goto exit;
        }

        // Get obj id, 0x2A864886F70D010702, 1.2.840.113549.1.7.2 signedData (PKCS #7)
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_OID)) != 0) {
            LOG_E("Get PKCS7 CERT 1.2.840.113549.1.7.2(signedData) failed");
            goto exit;
        }

        if ((len != sizeof(pkcs7_data_oid)) || (memcmp(p, &pkcs7_data_oid[0], len) != 0)) {
            LOG_E("PKCS7 CERT obj id is not 1.2.840.113549.1.7.2(signedData)");
            goto exit;
        }

        // Get Tag 0(content)
        p = p + len;
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONTEXT_SPECIFIC | SSS_UTIL_ASN1_CONSTRUCTED)) !=
            0) {
            LOG_E("Get PKCS7 CERT Tag 0(content) failed");
            goto exit;
        }

        // Get SEQ(SignedData)
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
            LOG_E("Get PKCS7 CERT SEQ (SignedData) failed");
            goto exit;
        }

        // Get INTEGER(version)
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_INTEGER)) != 0) {
            LOG_E("Get PKCS7 CERT SEQ (SignedData) failed");
            goto exit;
        }

        // Get SET(digestAlgorithms)
        p = p + len;
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SET)) != 0) {
            LOG_E("Get PKCS7 CERT SET (SignedData) failed");
            goto exit;
        }

        // Get SEQ(contentInfo)
        p = p + len;
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONSTRUCTED | SSS_UTIL_ASN1_SEQUENCE)) != 0) {
            LOG_E("Get PKCS7 CERT SEQ (contentInfo) failed");
            goto exit;
        }

        // Get Tag 0(certificates)
        p = p + len;
        if ((ret = sss_util_asn1_get_tag(&p, end, &len, SSS_UTIL_ASN1_CONTEXT_SPECIFIC | SSS_UTIL_ASN1_CONSTRUCTED)) !=
            0) {
            LOG_E("Get PKCS7 CERT Tag 0 (certificates) failed");
            goto exit;
        }

        const unsigned char *ptr = p;
        // Parse X.509 certificate.
        if (len > INT_MAX) {
            status = kStatus_SSS_Fail;
            goto exit;
        }
        x509 = d2i_X509(NULL, &ptr, (int)len);
        if (x509 == NULL) {
            LOG_E("Openssl parse certificates failed");
            goto exit;
        }
    }

    if (certType == kDeviceCert) {
        deviceCertCtx->deviceCert[certIndex] = x509;
    }
    else {
        deviceCertCtx->deviceCACertList[certIndex] = x509;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
#endif
}

/**
 * @brief         Get all CA certificate candidates.
 *
 *                Get Root CA certificate and parent certificates in cache.
 *                Parse these certificates and add to container.
 *
 * @param         pAuthCtx               Context Pointer to auth context.
 * @param[in]     deviceCertCtx          Context Pointer to device certificates.
 * @param[in]     seRootCert             SE root certificate buffer.
 * @param[in]     seRootCertLen          SE root certificate buffer length.
 * @param[out]    deviceCACertCacheBuf   Buffer to hold the cached the CA certificates.
 *
 * @return        Status of searching.
 */
sss_status_t nx_hostcrypto_get_CA_cert_list(nx_auth_sigma_ctx_t *pAuthCtx,
    nx_device_cert_ctx_host_t *deviceCertCtx,
    uint8_t *seRootCert,
    size_t seRootCertLen,
    uint8_t **deviceCACertCacheBuf)
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    sss_status_t status = kStatus_SSS_Fail;
    int counter         = 0;
    int i               = -1;
    uint8_t *pCertBuf   = NULL;
    size_t certBufLen   = 0;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(deviceCertCtx != NULL);
    ENSURE_OR_GO_EXIT(seRootCert != NULL);
    ENSURE_OR_GO_EXIT(deviceCACertCacheBuf != NULL);

    // Add Root CA certificate
    status = nx_hostcrypto_parse_x509_cert(
        deviceCertCtx, kDeviceCACert, NX_CA_CERT_LEVEL_ROOT - 1, seRootCert, seRootCertLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    counter++;

    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_get_parent_cert_from_cache != NULL);
    // Add certificate in cache
    for (i = 0; i < NX_MAX_CERT_DEPTH - 1; i++) {
        // Load device CA cache file.
        pCertBuf = (uint8_t *)SSS_MALLOC(NX_MAX_CERT_BUFFER_SIZE);
        ENSURE_OR_GO_EXIT(pCertBuf != NULL);
        memset(pCertBuf, 0, NX_MAX_CERT_BUFFER_SIZE);
        certBufLen = NX_MAX_CERT_BUFFER_SIZE;

        // ex_get_parent_cert_from_cache()
        status = kStatus_SSS_Fail;
        status = pAuthCtx->static_ctx.fp_get_parent_cert_from_cache(i, pCertBuf, &certBufLen);

        if (status == kStatus_SSS_Success) {
            *(deviceCACertCacheBuf + i) = pCertBuf;
            status                      = kStatus_SSS_Fail;
            status                      = nx_hostcrypto_parse_x509_cert(
                deviceCertCtx, kDeviceCACert, NX_CA_CERT_LEVEL_ROOT + i, pCertBuf, certBufLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            counter++;
        }
        else {
            *(deviceCACertCacheBuf + i) = NULL;
            if (pCertBuf != NULL) {
                memset(pCertBuf, 0, NX_MAX_CERT_BUFFER_SIZE);
                SSS_FREE(pCertBuf);
            }
        }
        status = kStatus_SSS_Success;
    }

    deviceCertCtx->deviceCACertListNum = counter;

exit:
    return status;

#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    sss_status_t status = kStatus_SSS_Fail;
    int x509_ret = 0;
    int i = -1;
    int counter = 0;
    uint8_t *pCertBuf = NULL;
    size_t certBufLen = 0;

    ENSURE_OR_GO_EXIT(pAuthCtx != NULL);
    ENSURE_OR_GO_EXIT(deviceCertCtx != NULL);
    ENSURE_OR_GO_EXIT(seRootCert != NULL);
    ENSURE_OR_GO_EXIT(deviceCACertCacheBuf != NULL);

    // Add Root CA certificate
    status = nx_hostcrypto_parse_x509_cert(
        deviceCertCtx, kDeviceCACert, NX_CA_CERT_LEVEL_ROOT - 1, seRootCert, seRootCertLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    counter++;

    status = kStatus_SSS_Fail;
    ENSURE_OR_GO_EXIT(pAuthCtx->static_ctx.fp_get_parent_cert_from_cache != NULL);

    // Add certificate in cache
    for (i = 0; i < NX_MAX_CERT_DEPTH - 1; i++) {
        status = kStatus_SSS_Fail;

        // Load device CA cache file.
        pCertBuf = (uint8_t *)SSS_MALLOC(NX_MAX_CERT_BUFFER_SIZE);
        ENSURE_OR_GO_EXIT(pCertBuf != NULL);
        memset(pCertBuf, 0, NX_MAX_CERT_BUFFER_SIZE);
        certBufLen = NX_MAX_CERT_BUFFER_SIZE;

        // ex_get_parent_cert_from_cache()
        status = kStatus_SSS_Fail;
        status = pAuthCtx->static_ctx.fp_get_parent_cert_from_cache(i, pCertBuf, &certBufLen);

        if (status == kStatus_SSS_Success) {
            *(deviceCACertCacheBuf + i) = pCertBuf;
            status = kStatus_SSS_Fail;
            status = nx_hostcrypto_parse_x509_cert(
                deviceCertCtx, kDeviceCACert, NX_CA_CERT_LEVEL_ROOT + i, pCertBuf, certBufLen);
            ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

            counter++;
        }
        else {
            *(deviceCACertCacheBuf + i) = NULL;
            if (pCertBuf != NULL) {
                memset(pCertBuf, 0, NX_MAX_CERT_BUFFER_SIZE);
                SSS_FREE(pCertBuf);
            }
        }
        status = kStatus_SSS_Success;
    }

    deviceCertCtx->deviceCACertListNum = counter;

    for (i = 0; i < counter; i++) {
        x509_ret = X509_STORE_add_cert(deviceCertCtx->rootCAStore, deviceCertCtx->deviceCACertList[i]);
        ENSURE_OR_GO_EXIT(1 == x509_ret);
    }

exit:
    return status;
#endif
}

/**
 * @brief         Get public key from a certificate container.
 *
 *                Parse device leaf certificate from deviceCertCtx and extract the device leaf public key.
 *
 * @param[in]     deviceCertCtx          Context Pointer to device certificates.
 * @param[out]     pubKeyBuf             Public key buffer.
 * @param[out]     pubKeyBufLen          Public key buffer length.
 *
 * @return        Status of extracting public key.
 */
sss_status_t nx_hostcrypto_get_pubkey_from_cert(
    nx_device_cert_ctx_host_t *deviceCertCtx, uint8_t *pubKeyBuf, size_t *pubKeyBufLen)
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != deviceCertCtx)
    ENSURE_OR_GO_EXIT(NULL != pubKeyBuf)
    ENSURE_OR_GO_EXIT(NULL != pubKeyBufLen)

    memcpy(pubKeyBuf, deviceCertCtx->deviceLeafCert.pk_raw.p, deviceCertCtx->deviceLeafCert.pk_raw.len);
    *pubKeyBufLen = deviceCertCtx->deviceLeafCert.pk_raw.len;

    status = kStatus_SSS_Success;
exit:
    return status;

#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    sss_status_t status = kStatus_SSS_Fail;
    EVP_PKEY *pEvpKey = NULL;
    int keyBufLen = 0;

    ENSURE_OR_GO_EXIT(NULL != deviceCertCtx)
    ENSURE_OR_GO_EXIT(NULL != pubKeyBuf)
    ENSURE_OR_GO_EXIT(NULL != pubKeyBufLen)

    // Get EVP_PKEY from certifictate
    pEvpKey = X509_get_pubkey(deviceCertCtx->deviceCert[NX_CERT_LEVEL_LEAF - 1]);
    ENSURE_OR_GO_EXIT(NULL != pEvpKey);

    // Get public key from EVP_PKEY
    keyBufLen = i2d_PUBKEY(pEvpKey, &pubKeyBuf);
    ENSURE_OR_GO_EXIT(keyBufLen > 0);

    *pubKeyBufLen = keyBufLen;

    status = kStatus_SSS_Success;
exit:
    return status;

#endif
}

/**
 * @brief         Verify cert chain with root cert.
 *
 *                The deviceCertCtx contains both the root CA and device certifcate.
 *                ECDSA-Verify_sk(SHA256(0x01 || (host ephem pub key) || (se ephem pub key) || AES-CMAK_k_tr(leaf cert hash)))
 *
 * @param[in]     deviceCertCtx         Pointer to device and CA certificate context.
 * @param[out]    valid                 Verify result.
 *
 * @return        Status of verify.
 */
sss_status_t nx_hostcrypto_verify_x509_cert(nx_device_cert_ctx_host_t *deviceCertCtx, bool *valid)
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    sss_status_t status = kStatus_SSS_Fail;
    uint32_t flags      = 0;
    int ret             = 0;
    int i               = -1;
    char subject[100]   = {0};
    size_t subjectLen   = sizeof(subject);

    ENSURE_OR_GO_EXIT(deviceCertCtx->deviceCACertList != NULL);
    ENSURE_OR_GO_EXIT(deviceCertCtx->deviceCACertListNum <= NX_MAX_CERT_DEPTH); // Root CA + cached CA
    ENSURE_OR_GO_EXIT(valid != NULL);

    *valid = false;
    for (i = 0; i < deviceCertCtx->deviceCACertListNum; i++) {
        ret = mbedtls_x509_crt_verify(
            &deviceCertCtx->deviceLeafCert, &deviceCertCtx->deviceCACertList[i], NULL, NULL, &flags, NULL, NULL);
        if (ret == 0) {
            mbedtls_x509_dn_gets(subject, subjectLen, &deviceCertCtx->deviceCACertList[i].subject);
            LOG_I("Verify X.509 certificate with certificate(%s) Passed", subject);
            *valid = true;
            break;
        }
    }

    if (*valid == false) {
        LOG_I("Verify X.509 certificate with root/cached CA certificate failed");
    }

    status = kStatus_SSS_Success;

exit:
    return status;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    int ret = -1;
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != deviceCertCtx->storeCtx);
    ENSURE_OR_GO_EXIT(NULL != deviceCertCtx->rootCAStore);
    ENSURE_OR_GO_EXIT(NULL != deviceCertCtx->deviceCert[NX_CERT_LEVEL_LEAF - 1]);
    ENSURE_OR_GO_EXIT(NULL != deviceCertCtx->caCertStack);
    ENSURE_OR_GO_EXIT(NULL != valid);

    X509_STORE_CTX_cleanup(deviceCertCtx->storeCtx);

    ret = X509_STORE_CTX_init(deviceCertCtx->storeCtx,
        deviceCertCtx->rootCAStore,
        deviceCertCtx->deviceCert[NX_CERT_LEVEL_LEAF - 1],
        deviceCertCtx->caCertStack);
    ENSURE_OR_GO_EXIT(ret == 1);

    ret = -1;
    ret = X509_verify_cert(deviceCertCtx->storeCtx);
    if (ret == 1) {
        *valid = true;
    }
    else {
        *valid = false;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
#endif
}

/**
 * @brief         Initialize the certificate containers for hostcrypto operations
 *
 * @param[in]     deviceCertCtx         Pointer to device and CA certificate context.
 *
 */
void nx_hostcrypto_cert_init(nx_device_cert_ctx_host_t *deviceCertCtx)
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    uint8_t i = 0;
    mbedtls_x509_crt_init(&deviceCertCtx->deviceLeafCert);
    for (i = 0; i < NX_MAX_CERT_DEPTH; i++) {
        mbedtls_x509_crt_init(&deviceCertCtx->deviceCACertList[i]);
    }
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    deviceCertCtx->rootCAStore = X509_STORE_new();
    deviceCertCtx->storeCtx = X509_STORE_CTX_new();
    deviceCertCtx->caCertStack = sk_X509_new_null();
#endif
}

/**
 * @brief         Build the certificate chain.
 *
 *                Build the certificate chain of CA certificates in the deviceCertCtx.
 *
 * @param[in]     deviceCertCtx         Pointer to device and CA certificate context.
 * @param[in]     certIndex             Certificate Index of the device certificate to be put in the chain.
 *
 */
sss_status_t nx_hostcrypto_push_intermediate_cert(nx_device_cert_ctx_host_t *deviceCertCtx, nx_cert_level_t certIndex)
{
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    return kStatus_SSS_Success;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(NULL != deviceCertCtx)

    sk_X509_push(deviceCertCtx->caCertStack, deviceCertCtx->deviceCert[certIndex]);

    status = kStatus_SSS_Success;

exit:
    return status;
#endif
}

/**
 * @brief         Free the certificate containers for hostcrypto operations
 *
 * @param[in]     deviceCertCtx         Pointer to device and CA certificate context.
 *
 */
void nx_hostcrypto_cert_free(nx_device_cert_ctx_host_t *deviceCertCtx)
{
    ENSURE_OR_GO_EXIT(NULL != deviceCertCtx)
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
    int i = -1;
    mbedtls_x509_crt_free(&deviceCertCtx->deviceLeafCert);
    for (i = 0; i < NX_MAX_CERT_DEPTH; i++) {
        mbedtls_x509_crt_free(&deviceCertCtx->deviceCACertList[i]);
    }
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
    size_t index = 0;
    for (index = 0; index < (sizeof(deviceCertCtx->deviceCert) / sizeof(X509 *)); index++) {
        if (deviceCertCtx->deviceCert[index] != NULL) {
            X509_free(deviceCertCtx->deviceCert[index]);
        }
    }
    for (index = 0; index < (sizeof(deviceCertCtx->deviceCACertList) / sizeof(X509 *)); index++) {
        if (deviceCertCtx->deviceCACertList[index] != NULL) {
            X509_free(deviceCertCtx->deviceCACertList[index]);
        }
    }
    sk_X509_pop_free(deviceCertCtx->caCertStack, X509_free);
    X509_STORE_CTX_cleanup(deviceCertCtx->storeCtx);
    X509_STORE_CTX_free(deviceCertCtx->storeCtx);
    X509_STORE_free(deviceCertCtx->rootCAStore);
#endif
exit:
    return;
}
#endif // SSS_HAVE_HOSTCRYPTO_ANY