/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "fsl_sss_nx_auth_types.h"
#include "fsl_sss_nx_auth_keys.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_Personalization.h"
#include "nx_apdu.h"
#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "mbedtls/asn1write.h"
#include "mbedtls/x509_crt.h"
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

sss_status_t nx_provision_get_default_host_cert(
    NX_CERTIFICATE_LEVEL_t level, Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_HOST_ROOT_CERT
    uint8_t hostRootCertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_HOST_ROOT_CERT;
#endif
#ifdef EX_SSS_SIGMA_I_NISTP256_HOST_ROOT_CERT
    uint8_t hostRootCertNistp256[] = EX_SSS_SIGMA_I_NISTP256_HOST_ROOT_CERT;
#endif
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_CERT
    uint8_t hostLeafCertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_CERT;
#endif
#ifdef EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_CERT
    uint8_t hostLeafCertNistp256[] = EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_CERT;
#endif

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((curveType == Nx_ECCurve_Brainpool256) || (curveType == Nx_ECCurve_NIST_P256));
    ENSURE_OR_GO_EXIT((level == NX_CERTIFICATE_LEVEL_LEAF) || (level == NX_CERTIFICATE_LEVEL_ROOT));

    if (level == NX_CERTIFICATE_LEVEL_ROOT) {
        if (curveType == Nx_ECCurve_Brainpool256) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_HOST_ROOT_CERT
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostRootCertBP256));
            memcpy(buffer, hostRootCertBP256, sizeof(hostRootCertBP256));
            *bufferLen = sizeof(hostRootCertBP256);
#else
            *bufferLen = 0;
#endif
        }
        else {
#ifdef EX_SSS_SIGMA_I_NISTP256_HOST_ROOT_CERT
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostRootCertNistp256));
            memcpy(buffer, hostRootCertNistp256, sizeof(hostRootCertNistp256));
            *bufferLen = sizeof(hostRootCertNistp256);
#else
            *bufferLen = 0;
#endif
        }
    }
    else {
        if (curveType == Nx_ECCurve_Brainpool256) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_HOST_LEAF_CERT
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostLeafCertBP256));
            memcpy(buffer, hostLeafCertBP256, sizeof(hostLeafCertBP256));
            *bufferLen = sizeof(hostLeafCertBP256);
#else
            *bufferLen = 0;
#endif
        }
        else {
#ifdef EX_SSS_SIGMA_I_NISTP256_HOST_LEAF_CERT
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostLeafCertNistp256));
            memcpy(buffer, hostLeafCertNistp256, sizeof(hostLeafCertNistp256));
            *bufferLen = sizeof(hostLeafCertNistp256);
#else
            *bufferLen = 0;
#endif
        }
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nx_provision_get_default_se_leaf_keypair(Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((curveType == Nx_ECCurve_Brainpool256) || (curveType == Nx_ECCurve_NIST_P256));

    if (curveType == Nx_ECCurve_Brainpool256) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_LEAF_KEYPAIR
        uint8_t seKeypairBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_LEAF_KEYPAIR;
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seKeypairBP256));
        memcpy(buffer, seKeypairBP256, sizeof(seKeypairBP256));
        *bufferLen = sizeof(seKeypairBP256);
#else
        *bufferLen = 0;
#endif
    }
    else {
#ifdef EX_SSS_SIGMA_I_NISTP256_DEVICE_LEAF_KEYPAIR
        uint8_t seKeypairNistp256[] = EX_SSS_SIGMA_I_NISTP256_DEVICE_LEAF_KEYPAIR;
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seKeypairNistp256));
        memcpy(buffer, seKeypairNistp256, sizeof(seKeypairNistp256));
        *bufferLen = sizeof(seKeypairNistp256);
#else
        *bufferLen = 0;
#endif
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nx_provision_get_default_se_cert(
    NX_CERTIFICATE_LEVEL_t level, Nx_ECCurve_t curveType, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((curveType == Nx_ECCurve_Brainpool256) || (curveType == Nx_ECCurve_NIST_P256));
    ENSURE_OR_GO_EXIT((level == NX_CERTIFICATE_LEVEL_LEAF) || (level == NX_CERTIFICATE_LEVEL_P1) ||
                      (level == NX_CERTIFICATE_LEVEL_P2));

    if (level == NX_CERTIFICATE_LEVEL_LEAF) {
        if (curveType == Nx_ECCurve_Brainpool256) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_LEAF_CERT
            uint8_t seLeafCertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_LEAF_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seLeafCertBP256));
            memcpy(buffer, seLeafCertBP256, sizeof(seLeafCertBP256));
            *bufferLen = sizeof(seLeafCertBP256);
#else
            *bufferLen = 0;
#endif
        }
        else if (curveType == Nx_ECCurve_NIST_P256) {
#ifdef EX_SSS_SIGMA_I_NISTP256_DEVICE_LEAF_CERT
            uint8_t seLeafCertNistp256[] = EX_SSS_SIGMA_I_NISTP256_DEVICE_LEAF_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seLeafCertNistp256));
            memcpy(buffer, seLeafCertNistp256, sizeof(seLeafCertNistp256));
            *bufferLen = sizeof(seLeafCertNistp256);
#else
            *bufferLen = 0;
#endif
        }
        else {
            LOG_E("Invalid cert curve type");
        }
    }
    else if (level == NX_CERTIFICATE_LEVEL_P1) {
        if (curveType == Nx_ECCurve_Brainpool256) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_P1_CERT
            uint8_t seP1CertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_P1_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seP1CertBP256));
            memcpy(buffer, seP1CertBP256, sizeof(seP1CertBP256));
            *bufferLen = sizeof(seP1CertBP256);
#else
            *bufferLen = 0;
#endif
        }
        else if (curveType == Nx_ECCurve_NIST_P256) {
#ifdef EX_SSS_SIGMA_I_NISTP256_DEVICE_P1_CERT
            uint8_t seP1CertNistp256[] = EX_SSS_SIGMA_I_NISTP256_DEVICE_P1_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seP1CertNistp256));
            memcpy(buffer, seP1CertNistp256, sizeof(seP1CertNistp256));
            *bufferLen = sizeof(seP1CertNistp256);
#else
            *bufferLen = 0;
#endif
        }
        else {
            LOG_E("Invalid cert curve type");
        }
    }
    else if (level == NX_CERTIFICATE_LEVEL_P2) {
        if (curveType == Nx_ECCurve_Brainpool256) {
#ifdef EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_P2_CERT
            uint8_t seP2CertBP256[] = EX_SSS_SIGMA_I_BRAINPOOL256_DEVICE_P2_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seP2CertBP256));
            memcpy(buffer, seP2CertBP256, sizeof(seP2CertBP256));
            *bufferLen = sizeof(seP2CertBP256);
#else
            *bufferLen = 0;
#endif
        }
        else if (curveType == Nx_ECCurve_NIST_P256) {
#ifdef EX_SSS_SIGMA_I_NISTP256_DEVICE_P2_CERT
            uint8_t seP2CertNistp256[] = EX_SSS_SIGMA_I_NISTP256_DEVICE_P2_CERT;
            ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(seP2CertNistp256));
            memcpy(buffer, seP2CertNistp256, sizeof(seP2CertNistp256));
            *bufferLen = sizeof(seP2CertNistp256);
#else
            *bufferLen = 0;
#endif
        }
        else {
            LOG_E("Invalid cert curve type");
        }
    }
    else {
        LOG_E("Invalid cert level");
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nx_provision_get_default_host_cert_mapping(
    NX_CERTIFICATE_LEVEL_t level, uint8_t *buffer, size_t *bufferLen)
{
    sss_status_t status = kStatus_SSS_Fail;
#ifdef EX_SSS_SIGMA_I_HOST_LEAF_CERT_MAPPING
    uint8_t hostLeafCertMapping[] = EX_SSS_SIGMA_I_HOST_LEAF_CERT_MAPPING;
#endif
#ifdef EX_SSS_SIGMA_I_HOST_P1_CERT_MAPPING
    uint8_t hostP1CertMapping[] = EX_SSS_SIGMA_I_HOST_P1_CERT_MAPPING;
#endif
#ifdef EX_SSS_SIGMA_I_HOST_P2_CERT_MAPPING
    uint8_t hostP2CertMapping[] = EX_SSS_SIGMA_I_HOST_P2_CERT_MAPPING;
#endif

    ENSURE_OR_GO_EXIT(buffer != NULL);
    ENSURE_OR_GO_EXIT(bufferLen != NULL);
    ENSURE_OR_GO_EXIT((level == NX_CERTIFICATE_LEVEL_LEAF) || (level == NX_CERTIFICATE_LEVEL_P1) ||
                      (level == NX_CERTIFICATE_LEVEL_P2));

    if (level == NX_CERTIFICATE_LEVEL_LEAF) {
#ifdef EX_SSS_SIGMA_I_HOST_LEAF_CERT_MAPPING
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostLeafCertMapping));
        memcpy(buffer, hostLeafCertMapping, sizeof(hostLeafCertMapping));
        *bufferLen = sizeof(hostLeafCertMapping);
#else
        *bufferLen = 0;
#endif
    }
    else if (level == NX_CERTIFICATE_LEVEL_P1) {
#ifdef EX_SSS_SIGMA_I_HOST_P1_CERT_MAPPING
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostP1CertMapping));
        memcpy(buffer, hostP1CertMapping, sizeof(hostP1CertMapping));
        *bufferLen = sizeof(hostP1CertMapping);
#else
        *bufferLen = 0;
#endif
    }
    else {
#ifdef EX_SSS_SIGMA_I_HOST_P2_CERT_MAPPING
        ENSURE_OR_GO_EXIT(*bufferLen >= sizeof(hostP2CertMapping));
        memcpy(buffer, hostP2CertMapping, sizeof(hostP2CertMapping));
        *bufferLen = sizeof(hostP2CertMapping);
#else
        *bufferLen = 0;
#endif
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}
