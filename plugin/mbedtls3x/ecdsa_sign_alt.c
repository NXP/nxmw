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

#ifdef MBEDTLS_ECDSA_SIGN_ALT

#include <string.h>
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/md.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/error.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/private_access.h"
#include "fsl_sss_api.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "ex_sss_boot.h"
#include "nx_apdu_tlv.h"
#include "nx_enums.h"
#include "nx_apdu.h"
#if SSS_HAVE_NX_TYPE
#include "fsl_sss_nx_apis.h"
#endif

#define ECDSA_BUDGET(ops)
#define ECDSA_RS_ENTER(SUB) (void)rs_ctx
#define ECDSA_RS_LEAVE(SUB) (void)rs_ctx
#define ECDSA_RS_ECP NULL

#define SSS_MAGIC_NUMBER (0xB6B5A6A5)
#define SSS_MAGIC_NUMBER_OFFSET1 (2)
#define SSS_MAGIC_NUMBER_OFFSET2 (6)
#define SSS_KEY_ID_IN_REFKEY_OFFSET (10)

static sss_key_store_t *g_ecdsa_sign_keystore = NULL;
ex_sss_boot_ctx_t g_nx_session_ctx            = {0};

static SE_ECSignatureAlgo_t nx_get_ec_sign_hash_mode(sss_algorithm_t algorithm);
/*
 * Set nx session
 */
void sss_mbedtls_set_keystore_ecdsa_sign(sss_key_store_t *ssskeystore)
{
    g_ecdsa_sign_keystore = ssskeystore;
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

int mbedtls_ecdsa_sign_restartable(mbedtls_ecp_group *grp,
    mbedtls_mpi *r,
    mbedtls_mpi *s,
    const mbedtls_mpi *d,
    const unsigned char *buf,
    size_t blen,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng,
    int (*f_rng_blind)(void *, unsigned char *, size_t),
    void *p_rng_blind,
    mbedtls_ecdsa_restart_ctx *rs_ctx)
{
    int ret, key_tries, sign_tries;
    int *p_sign_tries = &sign_tries, *p_key_tries = &key_tries;
    mbedtls_ecp_point R;
    mbedtls_mpi k, e, t;
    mbedtls_mpi *pk = &k, *pr = r;

    /* Fail cleanly on curves such as Curve25519 that can't be used for ECDSA */
    // if (!mbedtls_ecdsa_can_do(grp->id) || grp->N.p == NULL) {   =======> Commented for now, need to be fixed later
    //     return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    // }

    /* Make sure d is in range 1..n-1 */
    if (mbedtls_mpi_cmp_int(d, 1) < 0 || mbedtls_mpi_cmp_mpi(d, &grp->N) >= 0) {
        return MBEDTLS_ERR_ECP_INVALID_KEY;
    }

    mbedtls_ecp_point_init(&R);
    mbedtls_mpi_init(&k);
    mbedtls_mpi_init(&e);
    mbedtls_mpi_init(&t);

    ECDSA_RS_ENTER(sig);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        /* redirect to our context */
        p_sign_tries = &rs_ctx->sig->sign_tries;
        p_key_tries  = &rs_ctx->sig->key_tries;
        pk           = &rs_ctx->sig->k;
        pr           = &rs_ctx->sig->r;

        /* jump to current step */
        if (rs_ctx->sig->state == ecdsa_sig_mul) {
            goto mul;
        }
        if (rs_ctx->sig->state == ecdsa_sig_modn) {
            goto modn;
        }
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    *p_sign_tries = 0;
    do {
        if ((*p_sign_tries)++ > 10) {
            ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }

        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        *p_key_tries = 0;
        do {
            if ((*p_key_tries)++ > 10) {
                ret = MBEDTLS_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }

            MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, pk, f_rng, p_rng));

#if defined(MBEDTLS_ECP_RESTARTABLE)
            if (rs_ctx != NULL && rs_ctx->sig != NULL) {
                rs_ctx->sig->state = ecdsa_sig_mul;
            }

        mul:
#endif
            MBEDTLS_MPI_CHK(mbedtls_ecp_mul_restartable(grp, &R, pk, &grp->G, f_rng_blind, p_rng_blind, ECDSA_RS_ECP));
            MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pr, &R.MBEDTLS_PRIVATE(X), &grp->N));
        } while (mbedtls_mpi_cmp_int(pr, 0) == 0);

#if defined(MBEDTLS_ECP_RESTARTABLE)
        if (rs_ctx != NULL && rs_ctx->sig != NULL) {
            rs_ctx->sig->state = ecdsa_sig_modn;
        }

    modn:
#endif
        /*
         * Accounting for everything up to the end of the loop
         * (step 6, but checking now avoids saving e and t)
         */
        ECDSA_BUDGET(MBEDTLS_ECP_OPS_INV + 4);

        /*
         * Step 5: derive MPI from hashed message
         */
        MBEDTLS_MPI_CHK(derive_mpi(grp, &e, buf, blen));

        /*
         * Generate a random value to blind inv_mod in next step,
         * avoiding a potential timing leak.
         */
        MBEDTLS_MPI_CHK(mbedtls_ecp_gen_privkey(grp, &t, f_rng_blind, p_rng_blind));

        /*
         * Step 6: compute s = (e + r * d) / k = t (e + rd) / (kt) mod n
         */
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, pr, d));
        MBEDTLS_MPI_CHK(mbedtls_mpi_add_mpi(&e, &e, s));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(&e, &e, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(pk, pk, &t));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(pk, pk, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_inv_mod(s, pk, &grp->N));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mul_mpi(s, s, &e));
        MBEDTLS_MPI_CHK(mbedtls_mpi_mod_mpi(s, s, &grp->N));
    } while (mbedtls_mpi_cmp_int(s, 0) == 0);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (rs_ctx != NULL && rs_ctx->sig != NULL) {
        MBEDTLS_MPI_CHK(mbedtls_mpi_copy(r, pr));
    }
#endif

cleanup:
    mbedtls_ecp_point_free(&R);
    mbedtls_mpi_free(&k);
    mbedtls_mpi_free(&e);
    mbedtls_mpi_free(&t);

    ECDSA_RS_LEAVE(sig);

    return ret;
}
// LCOV_EXCL_STOP

int EcSignatureToRandS_alt(uint8_t *signature, size_t *sigLen, mbedtls_mpi *r, mbedtls_mpi *s)
{
    int ret = 1;
    ENSURE_OR_GO_EXIT(signature != NULL)
    ENSURE_OR_GO_EXIT(sigLen != NULL)
    ENSURE_OR_GO_EXIT(r != NULL)
    ENSURE_OR_GO_EXIT(s != NULL)

    unsigned char *p         = (unsigned char *)signature;
    const unsigned char *end = signature + *sigLen;
    size_t len               = 0;

    ret = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    ENSURE_OR_GO_EXIT(ret == 0)

    ret = MBEDTLS_ERROR_ADD(MBEDTLS_ERR_ECP_BAD_INPUT_DATA, MBEDTLS_ERR_ASN1_LENGTH_MISMATCH);
    ENSURE_OR_GO_EXIT(p + len == end)

    ret = mbedtls_asn1_get_mpi(&p, end, r);
    ENSURE_OR_GO_EXIT(ret == 0)

    ret = mbedtls_asn1_get_mpi(&p, end, s);

exit:
    return ret;
}

int mbedtls_ecdsa_sign_o(mbedtls_ecp_group *grp,
    mbedtls_mpi *r,
    mbedtls_mpi *s,
    const mbedtls_mpi *d,
    const unsigned char *buf,
    size_t blen,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    int ret = 1;
    ENSURE_OR_GO_EXIT(grp != NULL);
    ENSURE_OR_GO_EXIT(r != NULL);
    ENSURE_OR_GO_EXIT(s != NULL);
    ENSURE_OR_GO_EXIT(d != NULL);
    ret = mbedtls_ecdsa_sign_restartable(grp, r, s, d, buf, blen, f_rng, p_rng, f_rng, p_rng, NULL);
exit:
    return ret;
}

/*
    grp – The context for the elliptic curve to use. This must be initialized and have group parameters set, for example through mbedtls_ecp_group_load().
    r – The MPI context in which to store the first part the signature. This must be initialized.
    s – The MPI context in which to store the second part the signature. This must be initialized.
    d – The private signing key. This must be initialized.
    buf – The content to be signed. This is usually the hash of the original data to be signed. This must be a readable buffer of length blen Bytes. It may be NULL if blen is zero.
    blen – The length of buf in Bytes.
    f_rng – The RNG function. This must not be NULL.
    p_rng – The RNG context to be passed to f_rng. This may be NULL if f_rng doesn’t need a context parameter.
*/
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp,
    mbedtls_mpi *r,
    mbedtls_mpi *s,
    const mbedtls_mpi *d,
    const unsigned char *buf,
    size_t blen,
    int (*f_rng)(void *, unsigned char *, size_t),
    void *p_rng)
{
    uint8_t ref_key[128]      = {0};
    size_t ref_key_len        = sizeof(ref_key);
    uint32_t magic_no1        = 0;
    uint32_t magic_no2        = 0;
    int mbedtls_ret           = 0;
    sss_algorithm_t algorithm = kAlgorithm_None;

    LOG_D("mbedtls_ecdsa_sign (%s)", __FILE__);

    ENSURE_OR_RETURN_ON_ERROR(grp != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(r != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(s != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(d != NULL, 1);
    ENSURE_OR_RETURN_ON_ERROR(buf != NULL, 1);
    (void)f_rng;
    (void)p_rng;

    ref_key_len = mbedtls_mpi_size(d);
    mbedtls_ret = mbedtls_mpi_write_binary_le(d, ref_key, ref_key_len);
    ENSURE_OR_RETURN_ON_ERROR(mbedtls_ret == 0, mbedtls_ret);
    ENSURE_OR_RETURN_ON_ERROR(ref_key_len > (SSS_MAGIC_NUMBER_OFFSET2 + 3), 1);

    magic_no1 = (ref_key[SSS_MAGIC_NUMBER_OFFSET1 + 0] << 24) | (ref_key[SSS_MAGIC_NUMBER_OFFSET1 + 1] << 16) |
                (ref_key[SSS_MAGIC_NUMBER_OFFSET1 + 2] << 8) | ref_key[SSS_MAGIC_NUMBER_OFFSET1 + 3];
    magic_no2 = (ref_key[SSS_MAGIC_NUMBER_OFFSET2 + 0] << 24) | (ref_key[SSS_MAGIC_NUMBER_OFFSET2 + 1] << 16) |
                (ref_key[SSS_MAGIC_NUMBER_OFFSET2 + 2] << 8) | ref_key[SSS_MAGIC_NUMBER_OFFSET2 + 3];
    // check for hash algorithm
    switch (blen) {
    case 32:
        algorithm = kAlgorithm_SSS_SHA256;
        break;
    default:
        algorithm = kAlgorithm_None;
    }

    // Check if the key is reference key
    if ((magic_no1 == SSS_MAGIC_NUMBER) && (magic_no2 == SSS_MAGIC_NUMBER) && (algorithm == kAlgorithm_SSS_SHA256)) {
        int ret                                    = 1;
        sss_status_t status                        = kStatus_SSS_Success;
        smStatus_t retStatus                       = SM_NOT_OK;
        uint8_t signature[256]                     = {0};
        size_t signatureLen                        = sizeof(signature);
        uint32_t key_id                            = {0};
        sss_key_store_t *sss_ecdsa_sign_keystore   = NULL;
        sss_nx_key_store_t *nx_ecdsa_sign_keystore = NULL;
        sss_nx_session_t *pSession                 = NULL;

        SE_ECSignatureAlgo_t ecSignAlgo                = kSE_ECSignatureAlgo_NA;
        uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {
            0,
        };
        size_t raw_signatureLen = sizeof(raw_signature);

        LOG_I("Reference key found. Use Secure element for ECDSA.");

        // Get Key id from Ref key
        key_id = ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 3];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_CLEANUP(key_id <= UINT32_MAX - ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 2]);
        key_id += ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 2];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_CLEANUP(key_id <= UINT32_MAX - ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 1]);
        key_id += ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 1];
        key_id = key_id << (1 * 8);
        ENSURE_OR_GO_CLEANUP(key_id <= UINT32_MAX - ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 0]);
        key_id += ref_key[SSS_KEY_ID_IN_REFKEY_OFFSET + 0];

        /*
        * Create a new session if keystore is not assigned
        */
        if (!g_ecdsa_sign_keystore) {
            char *portName = NULL;

            LOG_W(
                "NOTE: The ALT implementation will open and close the session. All transient objects will be lost. \n \
            To avoid the session open in ALT, Use the sss_mbedtls_set_keystore_ecdsa_sign() api to pass the keystore.");

            status = ex_sss_boot_connectstring(0, NULL, &portName);
            ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

            status = ex_sss_boot_open(&g_nx_session_ctx, portName);
            ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

            status = ex_sss_key_store_and_object_init(&g_nx_session_ctx);
            ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

            sss_ecdsa_sign_keystore = &(g_nx_session_ctx).ks;
            nx_ecdsa_sign_keystore  = (sss_nx_key_store_t *)sss_ecdsa_sign_keystore;
            pSession                = (sss_nx_session_t *)(nx_ecdsa_sign_keystore->session);
        }
        else {
            nx_ecdsa_sign_keystore = (sss_nx_key_store_t *)g_ecdsa_sign_keystore;
            pSession               = (sss_nx_session_t *)(nx_ecdsa_sign_keystore->session);
        }

        ecSignAlgo = nx_get_ec_sign_hash_mode(algorithm);
        if (ecSignAlgo == kSE_ECSignatureAlgo_NA) {
            LOG_E("Invalid algorithm 0x%x", ecSignAlgo);
            goto cleanup;
        }

        LOG_I("ECDSA Sign using NX SA");
        retStatus = nx_CryptoRequest_ECCSign_Digest_Oneshot(&pSession->s_ctx,
            ecSignAlgo,
            key_id,
            kSE_CryptoDataSrc_CommandBuf,
            (uint8_t *)buf,
            blen,
            raw_signature,
            &raw_signatureLen);
        if (retStatus != SM_OK) {
            LOG_E("nx_CryptoRequest_ECCSign_Digest_Oneshot Failed");
            goto cleanup;
        }

        status = sss_util_encode_asn1_signature(signature, &signatureLen, raw_signature, raw_signatureLen);
        if (status != kStatus_SSS_Success) {
            LOG_E("sss_util_encode_asn1_signature Failed");
            goto cleanup;
        }

        if (0 != EcSignatureToRandS_alt(signature, &signatureLen, r, s)) {
            LOG_E("EcSignatureToRandS_alt Failed");
            goto cleanup;
        }

        ret = 0;
    cleanup:

        if (g_ecdsa_sign_keystore == NULL) {
            LOG_I("Close nx session");
            ex_sss_session_close(&g_nx_session_ctx);
        }
        return ret;
    }
    else {
        LOG_I("Not a reference key. Rollback to software implementation of ecdsa sign");
        return mbedtls_ecdsa_sign_o(grp, r, s, d, buf, blen, f_rng, p_rng);
    }
}

#endif //#if MBEDTLS_ECDSA_SIGN_ALT