/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#define MAX_KEY_LEN 1024

void nxclitool_show_command_help_set_key()
{
    printf("\nUSAGE: nxclitool setkey [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -curve\tECC curve type. Accepted values:\n");
    printf("\t\t  prime256v1\n");
    printf("\t\t  brainpoolP256r1\n");
    printf("  -enable\tOperation to be performed by the key. Accepted values:\n");
    printf("\t\t  none\n");
    printf("\t\t  ecdh\n");
    printf("\t\t  sign\n");
    printf("  -in\t\tPath to the certificate/key in PEM format\n");
    printf("  -keyid\tECC private key ID associated with the repository\n");
    printf("\n");
}

sss_status_t nxclitool_set_key(int argc,
    const char *argv[],
    nxclitool_sss_boot_ctx_t *pCtx,
    uint32_t key_id,
    Nx_ECCurve_t curve_type,
    NXCLITOOL_OPERATION_t operation,
    char *file)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_object_t key_object       = {0};
    sss_key_part_t key_part       = kSSS_KeyPart_Pair; // By default Key pair in PEM format should be supplied
    sss_cipher_type_t cipher_type = kSSS_CipherType_NONE;
    size_t key_pair_len           = MAX_KEY_LEN;
    size_t key_len                = 256;
    unsigned char input_key[MAX_CERT_BUF_LEN + 1] = {0};
    uint8_t key_pair[MAX_KEY_LEN]                 = {0};
    uint8_t key[MAX_KEY_LEN]                      = {0};
    size_t input_len                              = sizeof(input_key);
    FILE *fp                                      = NULL;

    // Initial policy with sign and ECDH disabled
    sss_policy_u keyGenPolicy  = {.type = KPolicy_GenECKey,
        .policy                        = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .kucLimit              = 0,
                       .sdmEnabled            = 0,
                       .sigmaiEnabled         = 0,
                       .ecdhEnabled           = 0, // can be changed using command line
                       .eccSignEnabled        = 0, // can be changed using command line
                       .writeCommMode         = kCommMode_FULL,
                       .writeAccessCond       = Nx_AccessCondition_Free_Access,
                       .userCommMode          = Nx_CommMode_NA,
                   }}};
    sss_policy_t ec_key_policy = {.nPolicies = 1, .policies = {&keyGenPolicy}};

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

    switch (operation) {
    case NXCLITOOL_OPERATION_NONE:
        keyGenPolicy.policy.genEcKey.eccSignEnabled = 0;
        keyGenPolicy.policy.genEcKey.ecdhEnabled    = 0;
        break;
    case NXCLITOOL_OPERATION_SIGN:
        keyGenPolicy.policy.genEcKey.eccSignEnabled = 1;
        keyGenPolicy.policy.genEcKey.ecdhEnabled    = 0;
        break;
    case NXCLITOOL_OPERATION_ECDH:
        keyGenPolicy.policy.genEcKey.eccSignEnabled = 0;
        keyGenPolicy.policy.genEcKey.ecdhEnabled    = 1;
        break;
    default:
        LOG_E("Invalid Operation for setting key");
        goto cleanup;
    }

    if ((fp = fopen(file, "rb")) != NULL) {
        LOG_I("Using certificate/key at path \"%s\"", file);
        if (convert_pem_to_der(fp, input_key, input_len, key_pair, &key_pair_len) != 0) {
            LOG_E("Unable to convert from PEM to DER");
            if (0 != fclose(fp)) {
                LOG_W("Failed to close the file handle");
            }
            goto cleanup;
        }
        if (0 != fclose(fp)) {
            LOG_W("Failed to close the file handle");
            goto cleanup;
        }
    }
    else {
        LOG_E("Unable to open the certificate/key file at path \"%s\"", file);
        input_len = 0;
        goto cleanup;
    }

    // Convert the key from PEM format to DER format

    // Extract private key from the key pair
    status = nxclitool_provision_parse_keypair_get_private_key(key_pair, key_pair_len, key, &key_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
    // LOG_AU8_W(key, key_len);

    LOG_I("Using Key ID as 0x%X", key_id);

    status = sss_key_object_init(&key_object, &pCtx->ks);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status =
        sss_key_object_allocate_handle(&key_object, key_id, key_part, cipher_type, 256 / 8, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status =
        sss_key_store_set_key(&pCtx->ks, &key_object, key, key_len, key_len * 8, &ec_key_policy, sizeof(ec_key_policy));
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("The private key has been set at key ID 0x%X", key_id);
    status = kStatus_SSS_Success;

cleanup:
    if (key_object.keyStore != NULL) {
        sss_key_object_free(&key_object);
    }
    return status;
}
