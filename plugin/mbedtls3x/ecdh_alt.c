/*
 *  Elliptic curve Diffie-Hellman
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 * RFC 4492
 */

#include "common.h"

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>
#include "fsl_sss_api.h"
#include "fsl_sss_util_asn1_der.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "ex_sss_boot.h"
#include "nx_apdu_tlv.h"
#include "nx_enums.h"
#include "nx_apdu.h"
#if SSS_HAVE_NX_TYPE
#include "fsl_sss_nx_apis.h"
#endif /* SSS_HAVE_NX_TYPE */

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */

#define SSS_NX_TMP_DERIVE_KEY_ID (0x00000004) // Used on host

#define SSS_MAGIC_NUMBER (0xB6B5A6A5)
#define SSS_MAGIC_NUMBER_OFFSET1 (2)
#define SSS_MAGIC_NUMBER_OFFSET2 (6)
#define SSS_KEY_ID_IN_REFKEY_OFFSET (10)

static sss_key_store_t *g_ecdh_keystore = NULL;

/** Length of BRAINPOOL 256 header */
#define NX_BRAINPOOL_256_HEADER_LEN 27

/** Length of NIST-P (SECP 256 R1) header */
#define NX_NIST_256_HEADER_LEN 26
/*
 * Set nx session
 */
void sss_mbedtls_set_keystore_ecdh(sss_key_store_t *nx_keystore)
{
    g_ecdh_keystore = nx_keystore;
}
// LCOV_EXCL_START
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef mbedtls_ecdh_context mbedtls_ecdh_context_mbed;
#endif

static mbedtls_ecp_group_id mbedtls_ecdh_grp_id(const mbedtls_ecdh_context *ctx)
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ctx->grp.id;
#else
    return ctx->grp_id;
#endif
}

#if defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
static int ecdh_compute_shared_restartable(mbedtls_ecp_group *grp,
    mbedtls_mpi *z,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng,
    mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point P;

    mbedtls_ecp_point_init(&P);

    MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &P, d, Q, f_rng, p_rng, rs_ctx));

    if (mbedtls_ecp_is_zero(&P)) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(mbedtls_mpi_copy(z, &P.X));

cleanup:
    mbedtls_ecp_point_free(&P);

    return ret;
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int mbedtls_ecdh_compute_shared_o(mbedtls_ecp_group *grp,
    mbedtls_mpi *z,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    return ecdh_compute_shared_restartable(grp, z, Q, d, f_rng, p_rng, NULL);
}
// LCOV_EXCL_STOP

/*
* return asn1 header length
*/
static int mbedtls_get_header_and_bit_Length(int groupid, int *headerLen, int *bitLen)
{
    switch (groupid) {
    case MBEDTLS_ECP_DP_SECP256R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_nistp256_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 256;
        }
        break;
    case MBEDTLS_ECP_DP_BP256R1:
        if (headerLen != NULL) {
            *headerLen = der_ecc_bp256_header_len;
        }
        if (bitLen != NULL) {
            *bitLen = 256;
        }
        break;
    default:
        LOG_E("get_header_and_bit_Length: Group id not supported");
        return 1;
    }

    return 0;
}
int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp,
    mbedtls_mpi *z,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *d,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    int ret                              = -1;
    int headerLen                        = 0;
    int keyBitLen                        = 0;
    uint8_t otherPublicKey[256]          = {0};
    size_t otherPublickeyLen             = sizeof(otherPublicKey);
    uint8_t privateKey[128]              = {0};
    size_t privateKeylen                 = 0;
    uint8_t buf[256]                     = {0};
    size_t bufByteLen                    = sizeof(buf);
    smStatus_t sm_status                 = SM_NOT_OK;
    uint32_t magic_no1                   = 0;
    uint32_t magic_no2                   = 0;
    uint32_t key_id                      = 0;
    int mbedtls_ret                      = 0;
    uint8_t sharedSecret[32]             = {0};
    size_t sharedSecretLen               = sizeof(sharedSecret);
    sss_nx_key_store_t *nx_ecdh_keystore = NULL;
    sss_nx_session_t *pSession           = NULL;
    size_t keyOffset                     = 0;

    /* read the private key */
    if (g_ecdh_keystore != NULL && grp != NULL &&
        (grp->id == MBEDTLS_ECP_DP_SECP256R1 || grp->id == MBEDTLS_ECP_DP_BP256R1)) {
        nx_ecdh_keystore = (sss_nx_key_store_t *)g_ecdh_keystore;
        pSession         = (sss_nx_session_t *)(nx_ecdh_keystore->session);
        privateKeylen    = mbedtls_mpi_size(d);
        mbedtls_ret      = mbedtls_mpi_write_binary_le(d, privateKey, privateKeylen);
        ENSURE_OR_RETURN_ON_ERROR(mbedtls_ret == 0, mbedtls_ret);

        /* Check if Key is reference key or not */
        magic_no1 = (privateKey[SSS_MAGIC_NUMBER_OFFSET1 + 0] << 24) |
                    (privateKey[SSS_MAGIC_NUMBER_OFFSET1 + 1] << 16) | (privateKey[SSS_MAGIC_NUMBER_OFFSET1 + 2] << 8) |
                    privateKey[SSS_MAGIC_NUMBER_OFFSET1 + 3];
        magic_no2 = (privateKey[SSS_MAGIC_NUMBER_OFFSET2 + 0] << 24) |
                    (privateKey[SSS_MAGIC_NUMBER_OFFSET2 + 1] << 16) | (privateKey[SSS_MAGIC_NUMBER_OFFSET2 + 2] << 8) |
                    privateKey[SSS_MAGIC_NUMBER_OFFSET2 + 3];

        if ((magic_no1 == SSS_MAGIC_NUMBER) && (magic_no2 == SSS_MAGIC_NUMBER)) {
            LOG_I("Reference key found. Use Secure element for ECDH.");

            // Get Key id from Ref key
            key_id = privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 3];
            key_id = key_id << (1 * 8);
            ENSURE_OR_GO_EXIT(key_id <= UINT32_MAX - privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 2]);
            key_id += privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 2];
            key_id = key_id << (1 * 8);
            ENSURE_OR_GO_EXIT(key_id <= UINT32_MAX - privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 1]);
            key_id += privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 1];
            key_id = key_id << (1 * 8);
            ENSURE_OR_GO_EXIT(key_id <= UINT32_MAX - privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 0]);
            key_id += privateKey[SSS_KEY_ID_IN_REFKEY_OFFSET + 0];
        }
        else {
            LOG_I("Not a reference key. Rollback to software implementation of ECDH");
            return mbedtls_ecdh_compute_shared_o(grp, z, Q, d, f_rng, p_rng);
        }

        ret = mbedtls_get_header_and_bit_Length(grp->id, &headerLen, &keyBitLen);
        ENSURE_OR_GO_EXIT(ret == 0);

        /* read the other party public key */
        ret = mbedtls_ecp_point_write_binary(grp,
            Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED,
            &otherPublickeyLen,
            (otherPublicKey + headerLen),
            sizeof(otherPublicKey));
        ENSURE_OR_GO_EXIT(ret == 0);

        switch (grp->id) {
        case MBEDTLS_ECP_DP_SECP256R1:
            memcpy(otherPublicKey, gecc_der_header_nist256, der_ecc_nistp256_header_len);
            if ((SIZE_MAX - der_ecc_nistp256_header_len) < otherPublickeyLen) {
                return 1;
            }
            otherPublickeyLen = otherPublickeyLen + der_ecc_nistp256_header_len;
            keyOffset         = NX_NIST_256_HEADER_LEN;
            break;
        case MBEDTLS_ECP_DP_BP256R1:
            memcpy(otherPublicKey, gecc_der_header_bp256, der_ecc_bp256_header_len);
            if ((SIZE_MAX - der_ecc_bp256_header_len) < otherPublickeyLen) {
                return 1;
            }
            otherPublickeyLen = otherPublickeyLen + der_ecc_bp256_header_len;
            keyOffset         = NX_BRAINPOOL_256_HEADER_LEN;
            break;
        default:
            LOG_I("Unsupported ec group found");
            return 1;
        }

        /* Do derive key */
        LOG_I("ECDH using NX Secure Authenticator");

        sm_status = nx_CryptoRequest_ECDH_Oneshot(&pSession->s_ctx,
            (uint8_t)key_id,
            kSE_CryptoDataSrc_CommandBuf,
            otherPublicKey + keyOffset,
            otherPublickeyLen - keyOffset,
            sharedSecret,
            &sharedSecretLen,
            buf,
            &bufByteLen);
        if (sm_status != SM_OK) {
            LOG_E("error in nx_CryptoRequest_ECDH_Oneshot");
            goto exit;
        }
        ret = mbedtls_mpi_read_binary(z, sharedSecret, sharedSecretLen);
        ENSURE_OR_GO_EXIT(ret == 0);
    }
    else {
        LOG_I("Unsupported EC group. Rolling back to software implementation of ECDH");
        return mbedtls_ecdh_compute_shared_o(grp, z, Q, d, f_rng, p_rng);
    }

exit:

    return ret;
}

#endif /* MBEDTLS_ECDH_COMPUTE_SHARED_ALT */
#endif /* MBEDTLS_ECDH_C */