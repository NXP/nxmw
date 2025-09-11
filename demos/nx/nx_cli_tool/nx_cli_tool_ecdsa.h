/*
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#define MD_LEN_BYTES 32
/** Length of BRAINPOOL 256 header */
#define NX_BRAINPOOL_256_HEADER_LEN 27

/** Length of NIST-P (SECP 256 R1) header */
#define NX_NIST_256_HEADER_LEN 26

void nxclitool_show_command_help_sign_message()
{
    printf("\nUSAGE: nxclitool dgst-sign [OPTIONS]");
    printf("OPTIONS:\n");
    printf("  -keyid\tECC private key ID associated with the keypair: 0x00 to 0x04\n");
    printf("  -in\t\tPath to the digest data in txt format\n");
    printf("  -out\t\tWrite the signature to a file on this path\n");
    printf("\n");
}

void nxclitool_show_command_help_verify_signature()
{
    printf("\nUSAGE: nxclitool dgst-verify [OPTIONS]");
    printf("OPTIONS:\n");
    printf("  -curve\t\tECC curve type. Accepted values: prime256v1 or brainpoolP256r1\n");
    printf("  -pubkey\tPath to the public key in PEM format\n");
    printf("  -signature\tPath to the signature in txt format\n");
    printf("  -in\t\tPath to the digest data in txt format\n");
    printf("\n");
}

sss_status_t nxclitool_sign_message(
    nxclitool_sss_boot_ctx_t *pboot_ctx, uint32_t key_id, char *in_file, char *out_file, bool out_file_flag)
{
    sss_status_t status             = kStatus_SSS_Fail;
    smStatus_t retStatus            = SM_NOT_OK;
    SE_ECSignatureAlgo_t ecSignAlgo = kSE_ECSignatureAlgo_SHA_256;
    uint8_t digest[MD_LEN_BYTES]    = {0};
    size_t digestLen                = sizeof(digest);
    size_t bytes_written            = 0;
    FILE *input_fh                  = NULL;
    FILE *signature_fh              = NULL;
    sss_nx_session_t *pSession      = NULL;
    /* clang-format off */

    uint8_t signature[MAX_SIGNATURE_LEN]       = {0};
    size_t signatureLen                        = sizeof(signature);
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {
        0,
    };
    size_t raw_signatureLen = sizeof(raw_signature);

    ENSURE_OR_GO_CLEANUP(NULL != pboot_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != in_file);
    ENSURE_OR_GO_CLEANUP(NULL != out_file);

    pSession               = (sss_nx_session_t *)(&pboot_ctx->session);

    LOG_I("Using input at \"%s\"", in_file);
    if((input_fh = fopen(in_file, "rb")) != NULL) {
        digestLen = fread((char *)digest, sizeof(char), MD_LEN_BYTES, input_fh);
        if (digestLen > MD_LEN_BYTES) {
            LOG_E("Input Data is more then 32 bytes in file");
            if (0 != fclose(input_fh)) {
                LOG_W("Failed to close the file handle");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        if (0 != fclose(input_fh)) {
            LOG_E("Failed to close the file handle!");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
    else {
        LOG_E("Unable to open the digest file at path \"%s\"", in_file);
        goto cleanup;        
    }

    /* Do Signing */
    LOG_I("Do Signing");
    retStatus = nx_CryptoRequest_ECCSign_Digest_Oneshot(&((sss_nx_session_t *)pSession)->s_ctx,
        ecSignAlgo,
        key_id,
        kSE_CryptoDataSrc_CommandBuf,
        (uint8_t *)digest,
        digestLen,
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

    LOG_I("Signing Successful !!!");
    LOG_MAU8_I("signature", signature, signatureLen);

    if (out_file_flag) {
        LOG_I("Save Signature at %s", out_file);
        signature_fh = fopen(out_file, "wb");
        if (NULL == signature_fh) {
            LOG_W("Unable to open a file to save signature");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        bytes_written = fwrite((char *)signature, sizeof(unsigned char), signatureLen, signature_fh);
        if (bytes_written != signatureLen) {
            LOG_E("Failed to write the signature to file!!");
            if (0 != fclose(signature_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (0 != fclose(signature_fh)) {
            LOG_E("Failed to close the file handle!");
        }
    }
    else {
        LOG_W("No output file path provided. signature has not be saved in file system");
    }

cleanup:
    if (kStatus_SSS_Success == status && SM_OK == retStatus) {
        LOG_I("ECDSA Sign Successful !!!...");
    }
    else {
        LOG_E("ECDSA Sign Failed !!!...");
    }

    return status;
}

sss_status_t nxclitool_verify_signature(nxclitool_sss_boot_ctx_t *pboot_ctx,
    Nx_ECCurve_t curve_type,
    char *in_file,
    char *pubkey_file,
    char *signature_file)
{
    sss_status_t status                   = kStatus_SSS_Fail;
    smStatus_t retStatus                  = SM_NOT_OK;
    SE_ECSignatureAlgo_t ecSignAlgo       = kSE_ECSignatureAlgo_SHA_256;
    uint8_t digest[MD_LEN_BYTES]      = {0};
    size_t digestLen                  = sizeof(digest);
    FILE *input_fh                    = NULL;
    FILE *signatue_fh                 = NULL;
    FILE *pubkey_fh                   = NULL;
    sss_nx_session_t *pSession        = NULL;
    /* clang-format off */
    char pubKeyMarker[]                        = "PUBLIC KEY";
    uint8_t publickey[MAX_PUBLIC_KEY_LEN]      = {0};
    size_t publickeylen                        = sizeof(publickey);
    uint8_t signature[MAX_SIGNATURE_LEN]    = {0};
    size_t signatureLen                        = sizeof(signature);
    size_t keyoffset                               = 0;
    uint16_t result                                = Nx_ECVerifyResult_Fail;
    uint8_t raw_signature[NX_RAW_SIGNATURE_LENGTH] = {
        0,
    };
    size_t raw_signatureLen = sizeof(raw_signature);

    ENSURE_OR_GO_CLEANUP(NULL != pboot_ctx );
    ENSURE_OR_GO_CLEANUP(NULL != in_file );
    ENSURE_OR_GO_CLEANUP(NULL != pubkey_file );
    ENSURE_OR_GO_CLEANUP(NULL != signature_file );

    pSession               = (sss_nx_session_t *)(&pboot_ctx->session);

    if(curve_type == Nx_ECCurve_Brainpool256) {
        keyoffset    = NX_BRAINPOOL_256_HEADER_LEN;
    } else {
        keyoffset    = NX_NIST_256_HEADER_LEN;
    }

    LOG_I("Using input at \"%s\"", in_file);
    if((input_fh = fopen(in_file, "rb")) != NULL) {
        digestLen = fread((char *)digest, sizeof(char), MD_LEN_BYTES, input_fh);
        if (digestLen > MD_LEN_BYTES) {
            LOG_E("Input Data is more then 32 bytes in file");
            if (0 != fclose(input_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        if (0 != fclose(input_fh)) {
            LOG_E("Failed to close the file handle!");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
    else {
        LOG_E("Unable to open the input digest file at path \"%s\"", in_file);
        status = kStatus_SSS_Fail;
        goto cleanup;                
    }

    LOG_I("Using public key at \"%s\"", pubkey_file);
    if((pubkey_fh = fopen(pubkey_file, "rb")) != NULL) {
        if (nxclitool_convert_pem_to_der(pubkey_fh, publickey, &publickeylen, pubKeyMarker) != 0) {
            LOG_E("Unable to convert from PEM to DER");
            if (0 != fclose(pubkey_fh)) {
                LOG_W("Failed to close the file handle");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        if (0 != fclose(pubkey_fh)) {
            LOG_W("Failed to close the file handle");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    } 
    else {
        LOG_E("Unable to open the public file at path \"%s\"", pubkey_file);
        status = kStatus_SSS_Fail;
        goto cleanup;        
    }

    LOG_I("Using signature at \"%s\"", signature_file);
    if((signatue_fh = fopen(signature_file, "rb")) != NULL) {
        signatureLen = fread((char *)signature, sizeof(char), signatureLen, signatue_fh);
        if (signatureLen > MAX_SIGNATURE_LEN) {
            LOG_E("Signature length more then expected bytes in file");
            if (0 != fclose(signatue_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        if (0 != fclose(signatue_fh)) {
            LOG_E("Failed to close the file handle!");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
    else {
        LOG_E("Unable to open the signature file at path \"%s\"", signature_file);
        status = kStatus_SSS_Fail;
        goto cleanup;
    }
    
    if (keyoffset >= publickeylen) {
        LOG_E("Public Key is invalid !!!");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    LOG_I("Do Verification");
    LOG_MAU8_I("Public key", publickey, publickeylen);
    LOG_MAU8_I("Digest", digest, digestLen);
    LOG_MAU8_I("Signature", signature, signatureLen);

    status = sss_util_decode_asn1_signature(raw_signature, &raw_signatureLen, signature, signatureLen);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == status);

    retStatus = nx_CryptoRequest_ECCVerify_Digest_Oneshot(&((sss_nx_session_t *)pSession)->s_ctx,
        ecSignAlgo,
        curve_type,
        publickey + keyoffset,
        publickeylen - keyoffset,
        raw_signature,
        raw_signatureLen,
        kSE_CryptoDataSrc_CommandBuf,
        (uint8_t *)digest,
        digestLen,
        &result);
    ENSURE_OR_GO_CLEANUP(SM_OK == retStatus);
    ENSURE_OR_GO_CLEANUP(result == Nx_ECVerifyResult_OK);
    LOG_I("Verification Successful !!!");
cleanup:

    if (kStatus_SSS_Success == status && result == Nx_ECVerifyResult_OK) {
        LOG_I("ECDSA Verify Successful !!!...");
    }
    else {
        LOG_E("ECDSA Verify Failed !!!...");
    }

    return status;
}