/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

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
    printf("  -in\t\tPath to the key in PEM format\n");
    printf("  -keyid\tECC private key ID to set the key\n");
    printf("  -waccess\tWrite Access for key policy. Accepted values:\n");
    printf("\t\t  0x00 to 0x0C\tAuth Required\n");
    printf("\t\t  0x0D\t\tFree over I2C\n");
    printf("\t\t  0x0E\t\tFree Access\n");
    printf("\t\t  0x0F\t\tNo Access\n");
    printf("\n");
}

void nxclitool_show_command_help_list_eckey()
{
    printf("\nUSAGE: nxclitool list-eckey\n");
    printf("\n");
    printf("NOTE: list-eckey command does not require any additional arguments.\n");
    printf("\n");
}

sss_status_t nxclitool_set_key(int argc,
    const char *argv[],
    nxclitool_sss_boot_ctx_t *pCtx,
    uint32_t key_id,
    Nx_ECCurve_t curve_type,
    NXCLITOOL_OPERATION_t operation,
    uint8_t write_acc_cond,
    char *file)
{
    sss_status_t status           = kStatus_SSS_Fail;
    sss_object_t key_object       = {0};
    sss_key_part_t key_part       = kSSS_KeyPart_Pair; // By default Key pair in PEM format should be supplied
    sss_cipher_type_t cipher_type = kSSS_CipherType_NONE;
    size_t key_pair_len           = MAX_KEY_LEN;
    size_t key_len                = 256;
    uint8_t key_pair[MAX_KEY_LEN] = {0};
    uint8_t key[MAX_KEY_LEN]      = {0};
    FILE *fp                      = NULL;
    char name[]                   = "EC PRIVATE KEY";

    ENSURE_OR_GO_CLEANUP(write_acc_cond <= 0x0F);

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
                       .writeAccessCond       = write_acc_cond,
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

    switch (write_acc_cond) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
        LOG_I("Using write access condition as AUTH REQUIRED 0x%X", write_acc_cond);
        break;
    case 0x0D:
        LOG_I("Using write access condition as FREE OVER I2C");
        break;
    case 0x0E:
        LOG_I("Using write access condition as FREE ACCESS");
        break;
    case 0x0F:
        LOG_I("Using write access condition as NO ACCESS");
        break;
    default:
        LOG_E("Invalid write access condition");
        break;
    }

    if ((fp = fopen(file, "rb")) != NULL) {
        LOG_I("Using certificate/key at path \"%s\"", file);
        if (nxclitool_convert_pem_to_der(fp, key_pair, &key_pair_len, name) != 0) {
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

sss_status_t nxclitool_list_eckey(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                                                        = kStatus_SSS_Fail;
    smStatus_t sm_status                                                       = SM_NOT_OK;
    sss_nx_session_t *pSession                                                 = NULL;
    uint8_t entry_count                                                        = NX_KEY_SETTING_ECC_KEY_MAX_ENTRY;
    int i                                                                      = 0;
    nx_ecc_key_meta_data_t eccPrivateKeyList[NX_KEY_SETTING_ECC_KEY_MAX_ENTRY] = {0};
    nx_ecc_key_meta_data_t empty_key_info                                      = {0};

    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status = nx_GetKeySettings_ECCPrivateKeyList(&pSession->s_ctx, &entry_count, eccPrivateKeyList);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    printf("\n");
    LOG_I("EC Key List:");

    for (i = 0; i < NX_KEY_SETTING_ECC_KEY_MAX_ENTRY; i++) {
        printf("\n");
        LOG_MAU8_D(
            "Plain ECC Private Key Info", (unsigned char *)&eccPrivateKeyList[i], sizeof(nx_ecc_key_meta_data_t));
        if (memcmp(&eccPrivateKeyList[i], &empty_key_info, sizeof(Nx_ECC_meta_data_t)) == 0) {
            // Nothing to print if the buffer is empty i.e. Key is not present
            continue;
        }
        LOG_I("   Key ID: 0x%0X", eccPrivateKeyList[i].keyId);

        switch (eccPrivateKeyList[i].curveId) {
        case Nx_ECCurve_NA:
            LOG_I("   Curve: NA");
            break;
        case Nx_ECCurve_NIST_P256:
            LOG_I("   Curve: NIST P256");
            break;
        case Nx_ECCurve_Brainpool256:
            LOG_I("   Curve: BRAINPOOL 256");
            break;
        default:
            LOG_I("   Curve: INVALID CURVE");
            break;
        }

        LOG_I("   Policy: 0x%0X", eccPrivateKeyList[i].keyPolicy);

        switch (eccPrivateKeyList[i].writeCommMode) {
        case Nx_CommMode_Plain:
            LOG_I("   Comm Mode: PLAIN");
            break;
        case Nx_CommMode_MAC:
            LOG_I("   Comm Mode: MAC");
            break;
        case Nx_CommMode_FULL:
            LOG_I("   Comm Mode: FULL");
            break;
        case Nx_CommMode_NA:
            LOG_I("   Comm Mode: NA");
            break;

        default:
            LOG_I("   Comm Mode: INVALID");
            break;
        }

        switch (eccPrivateKeyList[i].writeAccessCond) {
        case Nx_AccessCondition_Free_Over_I2C:
            LOG_I("   Write access: FREE OVER I2C");
            break;
        case Nx_AccessCondition_Free_Access:
            LOG_I("   Write access: FREE ACCESS");
            break;
        case Nx_AccessCondition_No_Access:
            LOG_I("   Write access: NO ACCESS");
            break;

        default:
            if (eccPrivateKeyList[i].writeAccessCond < 0x0D) {
                LOG_I("   Write access: AUTH REQUIRED 0x%0X", eccPrivateKeyList[i].writeAccessCond);
            }
            else {
                LOG_I("   Write access: INVALID");
            }
            break;
        }

        LOG_I("   Key Usage Counter Limit: %d", eccPrivateKeyList[i].kucLimit);
        LOG_I("   Key Usage Counter: %d", eccPrivateKeyList[i].keyUsageCtr);
    }
    status = kStatus_SSS_Success;

exit:
    return status;
}