/*
 *  Elliptic curve DSA
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/mbedtls_config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#ifdef MBEDTLS_ECDSA_VERIFY_ALT

#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/private_access.h"
#include "fsl_sss_api.h"
#include "fsl_sss_util_asn1_der.h"
#include "ex_sss_boot.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "nx_apdu_tlv.h"
#include "nx_enums.h"
#include "nx_apdu.h"
#if SSS_HAVE_NX_TYPE
#include "fsl_sss_nx_apis.h"
#endif

/** Length of BRAINPOOL 256 header */
#define NX_BRAINPOOL_256_HEADER_LEN 27

/** Length of NIST-P (SECP 256 R1) header */
#define NX_NIST_256_HEADER_LEN 26

static sss_key_store_t *g_ecdsa_verify_keystore = NULL;
ex_sss_boot_ctx_t g_alt_nx_session_ctx          = {0};

#define ECDSA_BUDGET(ops)
#define ECDSA_RS_ENTER(SUB) (void)rs_ctx
#define ECDSA_RS_LEAVE(SUB) (void)rs_ctx
#define ECDSA_RS_ECP NULL

static SE_ECSignatureAlgo_t nx_get_ec_sign_hash_mode(sss_algorithm_t algorithm);
/*
 * Set nx session
 */
void sss_mbedtls_set_keystore_ecdsa_verify(sss_key_store_t *ssskeystore)
{
    g_ecdsa_verify_keystore = ssskeystore;
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
// LCOV_EXCL_START
/*
 * Compute ECDSA signature of a hashed message
 */
static int derive_mpi(const mbedtls_ecp_group *grp, mbedtls_mpi *x, const unsigned char *buf, size_t blen)
{
    int ret         = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n_size   = (grp->nbits + 7) / 8;
    size_t use_size = blen > n_size ? n_size : blen;

    MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(x, buf, use_size));
    if (use_size * 8 > grp->nbits) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_shift_r(x, use_size * 8 - grp->nbits));
    }

    /* While at it, reduce modulo N */
    if (mbedtls_mpi_cmp_mpi(x, &grp->N) >= 0) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_sub_mpi(x, x, &grp->N));
    }

cleanup:
    return ret;
}

/*
 * Verify ECDSA signature of hashed message
 */

int mbedtls_ecdsa_verify_restartable(mbedtls_ecp_group *grp,
    const unsigned char *buf,
    size_t blen,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *r,
    const mbedtls_mpi *s,
    mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_mpi e, s_inv, u1, u2;
    mbedtls_ecp_point R;
    mbedtls_mpi *pu1 = &u1, *pu2 = &u2;

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&s_inv);
    mbedtls_mpi_init(&u1);
    mbedtls_mpi_init(&u2);

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.MBEDTLS_PRIVATE(p) == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    ECDSA_RS_ENTER(ver);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        /* redirect to our context */
        pu1 = &rs_ctx->ver->u1;
        pu2 = &rs_ctx->ver->u2;

        /* jump to current step */
        if (rs_ctx->ver->state == ecdsa_ver_muladd) {
            goto muladd;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if (mbedtls_mpi_cmp_int(r, 1) < 0 || mbedtls_mpi_cmp_mpi(r, &grp->N) >= 0 || mbedtls_mpi_cmp_int(s, 1) < 0 ||
        mbedtls_mpi_cmp_mpi(s, &grp->N) >= 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 3: derive MPI from hashed message
     */
    MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

    /*
     * Step 4: u1 = e / s mod n, u2 = r / s mod n
     */
    ECDSA_BUDGET(MBEDTLS_ECP_OPS_CHK + MBEDTLS_ECP_OPS_INV + 2);

    MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(&s_inv, s, &grp->N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu1, &e, &s_inv));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu1, pu1, &grp->N));

    MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pu2, r, &s_inv));
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pu2, pu2, &grp->N));

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->ver != NULL) {
        rs_ctx->ver->state = ecdsa_ver_muladd;
    }

muladd:
#endif
    /*
     * Step 5: R = u1 G + u2 Q
     */
    MBEDTLS_MPI_CHK(mbedtls_ecp_muladd_restartable(grp, &R, pu1, &grp->G, pu2, Q, ECDSA_RS_ECP));

    if (mbedtls_ecp_is_zero(&R)) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n (gives v)
     */
    MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(&R.MBEDTLS_PRIVATE(X), &R.MBEDTLS_PRIVATE(X), &grp->N));

    /*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if (mbedtls_mpi_cmp_mpi(&R.MBEDTLS_PRIVATE(X), r) != 0) {
        ret = MBEDTLS_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&s_inv);
    mbedtls_mpi_free(&u1);
    mbedtls_mpi_free(&u2);

    ECDSA_RS_LEAVE(ver);

    return ret;
}
// LCOV_EXCL_STOP

int mbedtls_ecdsa_verify_o(mbedtls_ecp_group *grp,
    const unsigned char *buf,
    size_t blen,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *r,
    const mbedtls_mpi *s)
{
    return mbedtls_ecdsa_verify_restartable(grp, buf, blen, Q, r, s, NULL);
}
/*
grp – The ECP group to use. This must be initialized and have group parameters set, for example through mbedtls_ecp_group_load().
buf – The hashed content that was signed. This must be a readable buffer of length blen Bytes. It may be NULL if blen is zero.
blen – The length of buf in Bytes.
Q – The public key to use for verification. This must be initialized and setup.
r – The first integer of the signature. This must be initialized.
s – The second integer of the signature. This must be initialized.
*/

int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
    const unsigned char *buf,
    size_t blen,
    const mbedtls_ecp_point *Q,
    const mbedtls_mpi *r,
    const mbedtls_mpi *s)
{
    int ret                                        = 1;
    uint8_t signature[256]                         = {0};
    uint8_t rs_buf[80]                             = {0};
    size_t signatureLen                            = 0;
    size_t rs_buf_len                              = 0;
    uint8_t publickey[256]                         = {0};
    size_t publickeylen                            = 0;
    size_t rawPublickeylen                         = 0;
    sss_algorithm_t algorithm                      = kAlgorithm_None;
    sss_status_t status                            = kStatus_SSS_Fail;
    char *portName                                 = NULL;
    uint16_t result                                = Nx_ECVerifyResult_Fail;
    sss_status_t asn_retval                        = kStatus_SSS_Fail;
    smStatus_t retStatus                           = SM_NOT_OK;
    SE_ECSignatureAlgo_t ecSignAlgo                = kSE_ECSignatureAlgo_NA;
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {0};
    size_t raw_signatureLen                        = sizeof(raw_signature);
    size_t keyoffset                               = 0;
    sss_key_store_t *sss_ecdsa_verify_keystore     = NULL;
    sss_nx_key_store_t *nx_ecdsa_verify_keystore   = NULL;
    sss_nx_session_t *pSession                     = NULL;
    Nx_ECCurve_t eCurveID                          = Nx_ECCurve_NA;

    LOG_D("mbedtls_ecdsa_verify (%s)", __FILE__);
    ENSURE_OR_GO_EXIT(grp != NULL)
    ENSURE_OR_GO_EXIT(buf != NULL)
    ENSURE_OR_GO_EXIT(Q != NULL)
    ENSURE_OR_GO_EXIT(r != NULL)
    ENSURE_OR_GO_EXIT(s != NULL)

    /*
    *  Create the signature
    *  Signature = {
    *  0x30, Remaining Length, Tag, R_length, R, Tag, S_length, S }
    */

    /* Set totoal length */
    signature[signatureLen++] = 0x30;
    if ((4 + mbedtls_mpi_size(r) + mbedtls_mpi_size(s)) > UINT8_MAX) {
        return -1;
    }
    signature[signatureLen++] = (unsigned char)(4 + mbedtls_mpi_size(r) + mbedtls_mpi_size(s));
    /* 4 ==> Tag + Lengthn + Tag + Length */

    /* Set R */
    rs_buf_len = mbedtls_mpi_size(r);
    ret        = mbedtls_mpi_write_binary(r, rs_buf, rs_buf_len);
    if (ret != 0) {
        return ret;
    }

    ret                       = -1;
    signature[signatureLen++] = 0x02;
    if ((rs_buf[0] & 0x80)) {
        ENSURE_OR_GO_EXIT(rs_buf_len + 1 <= UINT8_MAX);
        signature[signatureLen++] = (unsigned char)(rs_buf_len + 1);
        signature[signatureLen++] = 0x00;
        /* Increment total length */
        signature[1] += 1;
    }
    else {
        ENSURE_OR_GO_EXIT(rs_buf_len <= UINT8_MAX);
        signature[signatureLen++] = (unsigned char)rs_buf_len;
    }

    ENSURE_OR_GO_EXIT(signatureLen <= sizeof(signature));
    if ((sizeof(signature) - signatureLen) < rs_buf_len) {
        return -1;
    }
    ENSURE_OR_GO_EXIT(rs_buf_len <= sizeof(rs_buf));
    memcpy(&signature[signatureLen], rs_buf, rs_buf_len);
    signatureLen += rs_buf_len;

    /* Set S */
    rs_buf_len = mbedtls_mpi_size(s);
    ret        = mbedtls_mpi_write_binary(s, rs_buf, rs_buf_len);
    if (ret != 0) {
        return ret;
    }

    ret = -1;
    ENSURE_OR_GO_EXIT((signatureLen + 1) < sizeof(signature))
    signature[signatureLen++] = 0x02;
    if ((rs_buf[0] & 0x80)) {
        ENSURE_OR_GO_EXIT((signatureLen + 2) < sizeof(signature))
        ENSURE_OR_GO_EXIT(rs_buf_len + 1 <= UINT8_MAX);
        signature[signatureLen++] = (unsigned char)(rs_buf_len + 1);
        signature[signatureLen++] = 0x00;
        /* Increment total length */
        signature[1] += 1;
    }
    else {
        ENSURE_OR_GO_EXIT((signatureLen + 1) < sizeof(signature))
        ENSURE_OR_GO_EXIT(rs_buf_len <= UINT8_MAX);
        signature[signatureLen++] = (unsigned char)rs_buf_len;
    }

    ENSURE_OR_GO_EXIT(signatureLen <= sizeof(signature));
    if ((sizeof(signature) - signatureLen) < rs_buf_len) {
        return -1;
    }
    ENSURE_OR_GO_EXIT(rs_buf_len <= sizeof(rs_buf));
    memcpy(&signature[signatureLen], rs_buf, rs_buf_len);
    signatureLen += rs_buf_len;
    /* End of creating the signature*/

    switch (grp->id) {
    case MBEDTLS_ECP_DP_SECP256R1:
        memcpy(publickey, gecc_der_header_nist256, der_ecc_nistp256_header_len);
        publickeylen = der_ecc_nistp256_header_len;
        eCurveID     = Nx_ECCurve_NIST_P256;
        keyoffset    = NX_NIST_256_HEADER_LEN;
        break;
    case MBEDTLS_ECP_DP_BP256R1:
        memcpy(publickey, gecc_der_header_bp256, der_ecc_bp256_header_len);
        publickeylen = der_ecc_bp256_header_len;
        eCurveID     = Nx_ECCurve_Brainpool256;
        keyoffset    = NX_BRAINPOOL_256_HEADER_LEN;
        break;
    default:
        LOG_I("Unsupported ec group found. Rolling back to software implementation of ecdsa verify");
        return mbedtls_ecdsa_verify_o(grp, buf, blen, Q, r, s);
    }

    // Check for SHA Algorithm
    switch (blen) {
    case 32:
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    default:
        LOG_I("Unsupported ec group found. Rolling back to software implementation of ecdsa verify");
        return mbedtls_ecdsa_verify_o(grp, buf, blen, Q, r, s);
    }

    ret = mbedtls_ecp_point_write_binary(
        grp, Q, 0, &rawPublickeylen, &publickey[publickeylen], (sizeof(publickey) - publickeylen));
    ENSURE_OR_GO_EXIT(ret == 0);
    ret = 1;
    publickeylen += rawPublickeylen;

    if (!g_ecdsa_verify_keystore) {
        LOG_W(
            "NOTE: The ALT implementation will open and close the session. All transient objects will be lost. \n \
        To avoid the session open in ALT, Use the sss_mbedtls_set_keystore_ecdsa_verify() api to pass the keystore.");

        status = ex_sss_boot_connectstring(0, NULL, &portName);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = ex_sss_boot_open(&g_alt_nx_session_ctx, portName);
        ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

        status = ex_sss_key_store_and_object_init(&g_alt_nx_session_ctx);
        ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

        sss_ecdsa_verify_keystore = &(g_alt_nx_session_ctx).ks;
        nx_ecdsa_verify_keystore  = (sss_nx_key_store_t *)sss_ecdsa_verify_keystore;
        pSession                  = (sss_nx_session_t *)(nx_ecdsa_verify_keystore->session);
    }
    else {
        nx_ecdsa_verify_keystore = (sss_nx_key_store_t *)g_ecdsa_verify_keystore;
        pSession                 = (sss_nx_session_t *)(nx_ecdsa_verify_keystore->session);
    }

    ecSignAlgo = nx_get_ec_sign_hash_mode(algorithm);
    if (ecSignAlgo == kSE_ECSignatureAlgo_NA) {
        LOG_E("Invalid algorithm 0x%x", ecSignAlgo);
        goto exit;
    }

    asn_retval = sss_util_decode_asn1_signature(raw_signature, &raw_signatureLen, signature, signatureLen);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == asn_retval);

    LOG_I("ECDSA Verify using NX SA");
    retStatus = nx_CryptoRequest_ECCVerify_Digest_Oneshot(&pSession->s_ctx,
        ecSignAlgo,
        eCurveID,
        publickey + keyoffset,
        publickeylen - keyoffset,
        raw_signature,
        raw_signatureLen,
        kSE_CryptoDataSrc_CommandBuf,
        (uint8_t *)buf,
        blen,
        &result);
    ENSURE_OR_GO_EXIT(SM_OK == retStatus);
    ENSURE_OR_GO_EXIT(result == Nx_ECVerifyResult_OK);

    ret = 0;
exit:
    if (g_ecdsa_verify_keystore == NULL) {
        LOG_I("Close NX session");
        ex_sss_session_close(&g_alt_nx_session_ctx);
    }
    return ret;
}

#endif //#ifdef MBEDTLS_ECDSA_VERIFY_ALT