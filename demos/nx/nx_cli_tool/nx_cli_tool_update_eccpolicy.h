/*
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#define PUBKEY_LEN_MAX 92

#define LOG_BIT(policy, bit, label_enabled, label_disabled) \
    LOG_I("Bit %2d: %s", bit, ((policy >> bit) & 0x1) ? label_enabled : label_disabled)
#define NXCLITOOL_ECC_KEYPOLICY_VALID_BITS_MASK 0x813C
#define NXCLITOOL_MGMT_KEYPAIR_POLICY_ECDH_DISABLED 0xF7
#define NXCLITOOL_MGMT_KEYPAIR_POLICY_ECC_SIGN_DISABLED 0xEF
void nxclitool_show_command_help_update_eccpolicy()
{
    printf("\nUSAGE: nxclitool update-eccpolicy [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf(
        "  -keyid:(required)\tKey ID for asymmetric key pair in NX SE. Key ID should be in HEX format. Example: 0x02. "
        "Accepted "
        "range:\n");
    printf("\t\t  0x00 to 0x04\n");
    printf("\n");
    printf("  -keypolicy <hex>:(required)\tECC Key Policy.\n");
    printf("\t\t  Bits:\n");
    printf("\t\t    Bit 2  - SIGMA-I Mutual Authentication\n");
    printf("\t\t    Bit 3  - ECC DH\n");
    printf("\t\t    Bit 4  - ECC Sign\n");
    printf("\t\t    Bit 5  - ECC-based Secure Dynamic Messaging\n");
    printf("\t\t    Bit 8  - ECC-based Card-Unilateral Auth\n");
    printf("\t\t    Bit 15 - Freeze KeyUsageCtrLimit\n");
    printf("\n");
    printf("NOTE:\n");
    printf("  ECC DH and ECC Sign cannot be enabled simultaneously. Choose one based on your use case.\n");
    printf("\n");
    printf("  -wcomm:(optional)\tWrite Communication Mode, required to set ecc key. Accepted values:\n");
    printf("\t\t  full\n");
    printf("\t\t  mac\n");
    printf("\t\t  na\n");
    printf("\t\t  plain\n");
    printf("\n");
    printf("  -waccess:(optional)\tWrite Access for key policy. Accepted values:\n");
    printf("\t\t  0x00 to 0x0C\tAuth Required\n");
    printf("\t\t  0x0D\t\tFree over I2C\n");
    printf("\t\t  0x0E\t\tFree Access\n");
    printf("\t\t  0x0F\t\tNo Access\n");
    printf("\n");
    printf("  -kuclimit <hex>\tKey Usage Counter Limit (KUCLimit). Accepted values:\n");
    printf("\t\t  0x00000000\tDisable usage counter (no limit)\n");
    printf("\t\t  0x00000001 - 0xFFFFFFFF\tEnable usage counter with specified limit\n");
    printf("\n");
}

sss_status_t nxclitool_update_eccpolicy(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                                                        = kStatus_SSS_Fail;
    smStatus_t sm_status                                                       = SM_NOT_OK;
    sss_nx_session_t *pSession                                                 = NULL;
    uint32_t key_id                                                            = 0;
    uint8_t entry_count                                                        = NX_KEY_SETTING_ECC_KEY_MAX_ENTRY;
    nx_ecc_key_meta_data_t eccPrivateKeyList[NX_KEY_SETTING_ECC_KEY_MAX_ENTRY] = {0};
    nx_ecc_key_meta_data_t empty_key_info                                      = {0};
    int i                                                                      = 2;
    Nx_ECCurve_t curve_type                                                    = Nx_ECCurve_NIST_P256;
    Nx_CommMode_t write_comm_mode                                              = Nx_CommMode_FULL;
    Nx_AccessCondition_t write_access_cond                                     = Nx_AccessCondition_Auth_Required_0x0;
    uint16_t keypolicy                                                         = 0;
    uint32_t kuclimit                                                          = 0;
    bool key_id_flag                                                           = FALSE;
    bool write_comm_mode_flag                                                  = FALSE;
    bool write_access_cond_flag                                                = FALSE;
    bool keypolicy_flag                                                        = FALSE;
    bool kuclimit_flag                                                         = FALSE;
    Nx_MgtKeyPair_Act_t option                                                 = Nx_MgtKeyPair_Act_Update_Meta;
    int keyIndex                                                               = -1;

    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    if (i >= argc) {
        LOG_E("No options provided. Check usage below");
        return 1;
    }
    while (i < argc) {
        if (0 == strcmp(argv[i], "-keyid")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            key_id_flag = TRUE;
            status      = nxclitool_get_uint32_from_hex_text(argv[i], &key_id);
            ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
            i++;
        }
        else if (0 == strcmp(argv[i], "-keypolicy")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            keypolicy_flag = TRUE;
            status         = nxclitool_get_uint16_from_hex_text(argv[i], &keypolicy);
            ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
            if (keypolicy & NX_MGMT_KEYPAIR_POLICY_ECC_SIGN_ENABLED) {
                keypolicy &= NXCLITOOL_MGMT_KEYPAIR_POLICY_ECDH_DISABLED;
            }
            else if (keypolicy & NX_MGMT_KEYPAIR_POLICY_ECDH_ENABLED) {
                keypolicy &= NXCLITOOL_MGMT_KEYPAIR_POLICY_ECC_SIGN_DISABLED;
            }
            i++;
        }
        else if (0 == strcmp(argv[i], "-wcomm")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            write_comm_mode_flag = TRUE;
            if (nxclitool_get_comm_mode((char *)argv[i], &write_comm_mode)) {
                LOG_E("Invalid parameter for \"-wcomm\". Check usage below");
                return 1;
            }
            i++;
        }
        else if (0 == strcmp(argv[i], "-waccess")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            write_access_cond_flag = TRUE;
            if (nxclitool_get_access_cond((char *)argv[i], &write_access_cond)) {
                LOG_E("Invalid parameter for \"-waccess\". Check usage below");
                return 1;
            }
            i++;
        }
        else if (0 == strcmp(argv[i], "-kuclimit")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            kuclimit_flag = TRUE;
            status        = nxclitool_get_uint32_from_hex_text(argv[i], &kuclimit);
            ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
            i++;
        }
        else {
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            LOG_W("Ignoring the unrecognised option \"%s\" for this command", argv[i]);
            i++;
        }
    }

    if (!(key_id_flag && keypolicy_flag)) {
        if (!key_id_flag) {
            LOG_E("\"-keyid\" option is required for this operation. Refer usage for this command.");
            goto exit;
        }
        if (!keypolicy_flag) {
            LOG_E("\"-keypolicy\" option is required for this operation. Refer usage for this command.");
            goto exit;
        }
    }

    sm_status = nx_GetKeySettings_ECCPrivateKeyList(&pSession->s_ctx, &entry_count, eccPrivateKeyList);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    for (i = 0; i < NX_KEY_SETTING_ECC_KEY_MAX_ENTRY; i++) {
        if (memcmp(&eccPrivateKeyList[i], &empty_key_info, sizeof(Nx_ECC_meta_data_t)) == 0) {
            // Nothing to print if the buffer is empty i.e. Key is not present
            continue;
        }
        if (key_id == eccPrivateKeyList[i].keyId) {
            keyIndex   = i;
            curve_type = eccPrivateKeyList[i].curveId;
            if (write_comm_mode_flag == FALSE) {
                write_comm_mode = eccPrivateKeyList[i].writeCommMode;
            }
            if (write_access_cond_flag == FALSE) {
                write_access_cond = eccPrivateKeyList[i].writeAccessCond;
            }
            if (keypolicy_flag == FALSE) {
                keypolicy = eccPrivateKeyList[i].keyPolicy;
            }
            if (kuclimit_flag == FALSE) {
                kuclimit = eccPrivateKeyList[i].kucLimit;
            }
            break;
        }
    }

    if (keyIndex < 0) {
        LOG_E("Key with ID %d does not exist! line: %d", key_id, __LINE__);
        goto exit;
    }

    switch (curve_type) {
    case Nx_ECCurve_NIST_P256:
        LOG_I("Using curve type as NIST_P256");
        break;
    case Nx_ECCurve_Brainpool256:
        LOG_I("Using curve type as BRAINPOOL_256");
        break;
    default:
        LOG_E("Invalid curve type");
        goto exit;
    }

    if (write_comm_mode_flag) {
        switch (write_comm_mode) {
        case 0x00:
            LOG_I("Using write communication mode as PLAIN");
            break;
        case 0x01:
            LOG_I("Using write communication mode as MAC");
            break;
        case 0x03:
            LOG_I("Using write communication mode as FULL");
            break;
        case 0x7F:
            LOG_I("Using write communication mode as NA");
            break;
        default:
            LOG_E("Invalid write communication mode");
            goto exit;
        }
    }

    if (write_access_cond_flag) {
        switch (write_access_cond) {
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
            LOG_I("Using write access condition as AUTH REQUIRED 0x%X", write_access_cond);
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
            goto exit;
        }
    }

    if (keypolicy) {
        keypolicy &= NXCLITOOL_ECC_KEYPOLICY_VALID_BITS_MASK;
        LOG_BIT(keypolicy, 2, "SIGMA-I Mutual Authentication - Enabled", "SIGMA-I Mutual Authentication - Disabled");
        LOG_BIT(keypolicy, 3, "ECC DH - Enabled", "ECC DH - Disabled");
        LOG_BIT(keypolicy, 4, "ECC Sign - Enabled", "ECC Sign - Disabled");
        LOG_BIT(keypolicy,
            5,
            "ECC-based Secure Dynamic Messaging - Enabled",
            "ECC-based Secure Dynamic Messaging - Disabled");
        LOG_BIT(keypolicy, 8, "ECC-based Card-Unilateral Auth - Enabled", "ECC-based Card-Unilateral Auth - Disabled");
        LOG_BIT(keypolicy, 15, "Freeze KeyUsageCtrLimit - Enabled", "Freeze KeyUsageCtrLimit - Disabled");
    }

    if (kuclimit_flag) {
        if (kuclimit == 0x00000000) {
            LOG_I("KUCLimit: KeyUsageCtrLimit disabled");
        }
        else {
            LOG_I("KUCLimit: KeyUsageCtrLimit enabled with value 0x%08X (LSB first)", kuclimit);
        }
    }

    sm_status = nx_ManageKeyPair(&pSession->s_ctx,
        key_id,
        option,
        curve_type,
        keypolicy,
        write_comm_mode,
        write_access_cond,
        kuclimit,
        NULL,
        0x0,
        NULL,
        NULL,
        Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        LOG_E("Failed to update-eccpolicy");
        goto exit;
    }
    status = kStatus_SSS_Success;
exit:
    if (kStatus_SSS_Success == status) {
        LOG_I("Update Eccpolicy Success !!!...");
    }
    else {
        LOG_E("Update Eccpolicy Failed !!!...");
    }
    return status;
}