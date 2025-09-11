/*
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

/** Length of BRAINPOOL 256 header */
#define NX_BRAINPOOL_256_HEADER_LEN 27

/** Length of NIST-P (SECP 256 R1) header */
#define NX_NIST_256_HEADER_LEN 26

void nxclitool_show_command_help_derive_ecdh()
{
    printf("\nUSAGE: nxclitool derive-ecdh [OPTIONS]");
    printf("OPTIONS:\n");
    printf("  -keyid\tECDH private key ID associated with the keypair: 0x00 to 0x04\n");
    printf("  -curve\t\t ECDH curve type. Accepted values: prime256v1 or brainpoolP256r1\n");
    printf("  -peerkey\tPath to the public key in PEM format\n");
    printf("  -out\t\tPath to the sharedSecret in txt format\n");
    printf("\n");
}

sss_status_t nxclitool_derive_ecdh(nxclitool_sss_boot_ctx_t *pboot_ctx,
    uint32_t key_id,
    Nx_ECCurve_t curve_type,
    char *peerKey_file,
    char *shkey_file,
    bool shkey_file_flag)
{
    sss_status_t status        = kStatus_SSS_Fail;
    smStatus_t sm_status       = SM_NOT_OK;
    uint8_t otherPublicKey[92] = {0};
    size_t otherPublickeyLen   = sizeof(otherPublicKey);
    uint8_t buf[256]           = {0};
    size_t bufByteLen          = sizeof(buf);
    char pubKeyMarker[]        = "PUBLIC KEY";
    size_t bytes_written       = 0;
    /* clang-format off */
    uint8_t sharedSecret[32]             = {0};
    size_t sharedSecretLen               = sizeof(sharedSecret);
    sss_nx_session_t *pSession           = NULL;
    size_t keyOffset                     = 0;
    FILE *pubkey_fh                      = NULL;
    FILE *shkey_fh                       = NULL;

    ENSURE_OR_GO_CLEANUP(NULL != pboot_ctx);
    ENSURE_OR_GO_CLEANUP(NULL != peerKey_file);
    ENSURE_OR_GO_CLEANUP(NULL != shkey_file);

    pSession               = (sss_nx_session_t *)(&pboot_ctx->session);

    LOG_I("Using public key at \"%s\"", peerKey_file);
    if((pubkey_fh = fopen(peerKey_file, "rb")) != NULL) {
        if (nxclitool_convert_pem_to_der(pubkey_fh, otherPublicKey, &otherPublickeyLen, pubKeyMarker) != 0) {
        LOG_E("Unable to convert from PEM to DER");
            if (0 != fclose(pubkey_fh)) {
                LOG_W("Failed to close the file handle");
            }
            goto cleanup;
        }
        if (0 != fclose(pubkey_fh)) {
            LOG_W("Failed to close the file handle");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
    else {
        LOG_E("Unable to open the public key file at path \"%s\"", peerKey_file);
        goto cleanup;
    }

    if(curve_type == Nx_ECCurve_Brainpool256) {
        keyOffset    = NX_BRAINPOOL_256_HEADER_LEN;
    } else {
        keyOffset    = NX_NIST_256_HEADER_LEN;
    }
    if (keyOffset >= otherPublickeyLen) {
        LOG_E("otherParty Public Key is invalid !!!");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }
    LOG_MAU8_I("PeerPublicKey", otherPublicKey, otherPublickeyLen);
    /* Do Signing */
    sm_status = nx_CryptoRequest_ECDH_Oneshot(&((sss_nx_session_t *)pSession)->s_ctx,
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
        goto cleanup;
    }

    LOG_I("ECDH Successful !!!");
    LOG_MAU8_I("sharedSecret", sharedSecret, sharedSecretLen);

    if (shkey_file_flag) {
        LOG_I("Save sharedSecret key at file %s", shkey_file);
        shkey_fh = fopen(shkey_file, "wb");
        if (NULL == shkey_fh) {
            LOG_W("Unable to open a file to save sharedSecret");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        bytes_written = fwrite((char *)sharedSecret, sizeof(unsigned char), sharedSecretLen, shkey_fh);
        if (bytes_written != sharedSecretLen) {
            LOG_E("Failed to write the sharedSecret to file!!");
            if (0 != fclose(shkey_fh)) {
                LOG_E("Failed to close the sharedSecret file handle!");
            }
            status = kStatus_SSS_Fail;
            goto cleanup;
        }

        if (0 != fclose(shkey_fh)) {
            LOG_E("Failed to close the sharedSecret file handle!");
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
    }
    else {
        LOG_W("No output file path provided. sharedSecret has not be saved in file system");
    }
    status = kStatus_SSS_Success;
cleanup:
    if ((kStatus_SSS_Success == status) && (SM_OK == sm_status)) {
        LOG_I("ECDH key derivation Successful !!!...");
    }
    else {
        LOG_E("ECDH key derivation Failed !!!...");
    }

    return status;
}
