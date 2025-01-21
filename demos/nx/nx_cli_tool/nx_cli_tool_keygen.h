/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#define PUBKEY_LEN_MAX 92

void nxclitool_show_command_help_generate()
{
    printf("\nUSAGE: nxclitool genkey [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -curve:\tECC curve type. Accepted values:\n");
    printf("\t\t  prime256v1\n");
    printf("\t\t  brainpoolP256r1\n");
    printf("  [-out]:\t\tStores the public part of the generated key to a file on this path\n");
    printf(
        "  -keyid:\tKey ID for asymmetric key pair in NX SE. Key ID should be in HEX format. Example: 0x02. Accepted "
        "range:\n");
    printf("\t\t  0x00 to 0x04\n");
    printf("\n");
}

sss_status_t nxclitool_do_generate_key(int argc,
    const char *argv[],
    nxclitool_sss_boot_ctx_t *pboot_ctx,
    nx_connect_ctx_t *pconn_ctx,
    uint32_t key_id,
    Nx_ECCurve_t curve_type,
    char file_out_path[],
    bool file_out_flag)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_object_t key_object       = {0};
    sss_cipher_type_t cipher_type = kSSS_CipherType_EC_NIST_P;
    size_t key_byte_len           = 256;
    FILE *fh                      = NULL;

#if SSS_HAVE_NX_TYPE
    const sss_policy_u key_gen_policy = {.type = KPolicy_GenECKey,
        .policy                                = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 1,
                       .sigmaiEnabled         = 0,
                       .ecdhEnabled           = 0,
                       .eccSignEnabled        = 1,
                       .writeCommMode         = kCommMode_SSS_Full,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x0,
                       .kucLimit              = 0,
                       .userCommMode          = kCommMode_SSS_NA,
                   }}};
    sss_policy_t ec_key_policy        = {.nPolicies = 1, .policies = {&key_gen_policy}};
#endif

    LOG_I("Using Key ID as 0x%X", key_id);

    switch (curve_type) {
    case Nx_ECCurve_NA:
        LOG_I("Using curve type as NA");
        cipher_type = kSSS_CipherType_NONE;
        break;
    case Nx_ECCurve_NIST_P256:
        LOG_I("Using curve type as NIST_P256");
        cipher_type = kSSS_CipherType_EC_NIST_P;
        break;
    case Nx_ECCurve_Brainpool256:
        LOG_I("Using curve type as BRAINPOOL_256");
        cipher_type = kSSS_CipherType_EC_BRAINPOOL;
        break;
    default:
        LOG_E("Invalid curve type");
        break;
    }

    status = sss_key_store_context_init(&pboot_ctx->ks, &pboot_ctx->session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_init(&key_object, &pboot_ctx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &key_object, key_id, kSSS_KeyPart_Pair, cipher_type, key_byte_len, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

#if SSS_HAVE_NX_TYPE
    status = sss_key_store_generate_key(&pboot_ctx->ks, &key_object, 256, &ec_key_policy);
#else
    status = sss_key_store_generate_key(&pboot_ctx->ks, &key_object, 256, NULL);
#endif
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    LOG_I("Key generated at ID 0x%X", key_id);

    if (file_out_flag) {
        uint8_t key[PUBKEY_LEN_MAX] = {0};
        size_t key_len              = sizeof(key);
        size_t key_bit_len          = key_len * 8;
        char name[]                 = "PUBLIC KEY";
        status                      = kStatus_SSS_Fail;

        status = sss_key_store_get_key(&pboot_ctx->ks, &key_object, key, &key_len, &key_bit_len);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        fh = fopen(file_out_path, "wb");
        if (NULL == fh) {
            LOG_W("Unable to open a file to store the public key");
            goto cleanup;
        }

        LOG_I("Storing the public part of generated key at \"%s\"", file_out_path);
        if (0 != nxclitool_store_der_to_pem(fh, key, &key_len, name, sizeof(name))) {
            LOG_E("Could not store key to file!!");
            if (0 != fclose(fh)) {
                LOG_E("Failed to close the file handle!");
            }
            goto cleanup;
        }
        if (0 != fclose(fh)) {
            LOG_E("Failed to close the file handle!");
        }
        status = kStatus_SSS_Success;
    }
    else {
        LOG_W("No file path provided. Public key has not be saved in file system");
    }

cleanup:
    if (status != kStatus_SSS_Success) {
        LOG_E("Key generation failed...");
    }
    if (key_object.keyStore != NULL) {
        sss_key_object_free(&key_object);
    }
    return status;
}