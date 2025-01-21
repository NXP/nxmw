/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

void nxclitool_show_command_help_connect()
{
    printf("\nUSAGE: nxclitool connect [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -smcom\tHost device to connect to. Accepted values:\n");
    printf("\t\t  pcsc\t  To connect to the simulator via pcsc\n");
    printf("\t\t  vcom\t  To connect to the SA via vcom\n");
    printf("\t\t  t1oi2c  To connect to the SA via T=1oI2C\n");
    printf(
        "  -port  \tPort of the host device. Set the value to \"default\" to use the default port. If skipped, default "
        "port will be used\n");
    printf("  -auth  \tAuthentication type. Accepted values:\n");
    printf("\t\t  none\n");
    printf("\t\t  sigma_i_verifier\n");
    printf("\t\t  sigma_i_prover\n");
    printf("\t\t  symmetric\n");
    printf("  -sctunn\tSecure tunneling type. Accepted values:\n");
    printf("\t\t  none\n");
    printf("\t\t  ntag_aes128_aes256_ev2\n");
    printf("\t\t  ccm_aes256\n");
    printf("\t\t  ntag_aes128_ev2\n");
    printf("\t\t  ntag_aes256_ev2\n");
    printf("  -keyid\tKey ID (only required for symmetric auth). Accepted values: 0x00 - 0x04\n");
    printf("  -curve\tECC Curve type (only required for sigma auth type). Accepted values:\n");
    printf("\t\t  brainpoolP256r1\n");
    printf("\t\t  prime256v1\n");
    printf("\t\t  na\n");
    printf("  -repoid\tRepository ID in hex format (only required for sigma auth type)\n");
    printf("\n");
}

// Returns: 0 for SUCCESS, 1 for FAILURE
int nxclitool_fetch_connect_parameters(int argc,
    const char *argv[],
    char host_name[],
    char port_name[],
    nx_auth_type_t *auth_type,
    nx_secure_symm_type_t *secure_tunnel_type,
    uint8_t *key_id,
    uint8_t *repo_id,
    Nx_ECCurve_t *curve_type)
{
    sss_status_t status         = kStatus_SSS_Fail;
    bool host_name_flag         = FALSE;
    bool port_name_flag         = FALSE;
    bool auth_type_flag         = FALSE;
    bool secure_tunnel_flag     = FALSE;
    bool key_id_flag            = FALSE;
    bool repo_id_flag           = FALSE;
    bool curve_type_flag        = FALSE;
    uint32_t temp_uint32_holder = 0;
    int i                       = 2;

    if (argc < 3) {
        LOG_E("No options provided. Check usage below");
        return 1;
    }

    while (i < argc) {
        if (0 == strcmp(argv[i], "-smcom")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            host_name_flag = TRUE;
            strcpy(host_name, argv[i]);
            i++;
            continue;
        }
        else if (0 == strcmp(argv[i], "-port")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            port_name_flag = TRUE;
            strcpy(port_name, argv[i]);
            i++;
            continue;
        }
        else if (0 == strcmp(argv[i], "-auth")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            auth_type_flag = TRUE;
            if (0 == strcmp(argv[i], "none")) {
                *auth_type = knx_AuthType_None;
            }
            else if (0 == strcmp(argv[i], "sigma_i_verifier")) {
                *auth_type = knx_AuthType_SIGMA_I_Verifier;
            }
            else if (0 == strcmp(argv[i], "sigma_i_prover")) {
                *auth_type = knx_AuthType_SIGMA_I_Prover;
            }
            else if (0 == strcmp(argv[i], "symmetric")) {
                *auth_type = knx_AuthType_SYMM_AUTH;
            }
            else {
                LOG_E("Invalid parameter for \"-auth\"");
                return 1;
            }
            i++;
            continue;
        }
        else if (0 == strcmp(argv[i], "-sctunn")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            secure_tunnel_flag = TRUE;
            if (0 == strcmp(argv[i], "none")) {
                *secure_tunnel_type = knx_SecureSymmType_None;
            }
            else if (0 == strcmp(argv[i], "ntag_aes128_aes256_ev2")) {
                *secure_tunnel_type = knx_SecureSymmType_AES128_AES256_NTAG;
            }
            else if (0 == strcmp(argv[i], "ntag_aes128_ev2")) {
                *secure_tunnel_type = knx_SecureSymmType_AES128_NTAG;
            }
            else if (0 == strcmp(argv[i], "ntag_aes256_ev2")) {
                *secure_tunnel_type = knx_SecureSymmType_AES256_NTAG;
            }
            else {
                LOG_E("Invalid parameter for \"-sctunn\"");
                return 1;
            }
            i++;
            continue;
        }
        else if (0 == strcmp(argv[i], "-keyid")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            key_id_flag = TRUE;
            status      = nxclitool_get_uint32_from_hex_text(argv[i], &temp_uint32_holder);
            if (temp_uint32_holder > UINT8_MAX) {
                LOG_E("Invalid key ID");
                return 1;
            }
            *key_id = (uint8_t)temp_uint32_holder;
            ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
            i++;
            continue;
        }
        else if (0 == strcmp(argv[i], "-curve")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            curve_type_flag = TRUE;
            if (0 == strcmp(argv[i], "prime256v1")) {
                *curve_type = Nx_ECCurve_NIST_P256;
            }
            else if (0 == strcmp(argv[i], "brainpoolP256r1")) {
                *curve_type = Nx_ECCurve_Brainpool256;
            }
            else {
                LOG_E("Invalid parameter for \"-curve\"");
                return 1;
            }
            i++;
            continue;
        }
        else if (0 == strcmp(argv[i], "-repoid")) {
            i++;
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            repo_id_flag = TRUE;
            status       = nxclitool_get_uint32_from_hex_text(argv[i], &temp_uint32_holder);
            if (temp_uint32_holder > UINT8_MAX) {
                LOG_E("Invalid repo ID");
                return 1;
            }
            *repo_id = (uint8_t)temp_uint32_holder;
            ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
            i++;
            continue;
        }
        else {
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            LOG_W("Ignoring the unrecognised command \"%s\" for this operation", argv[i]);
            i++;
        }
    }

    if (!port_name_flag) {
        strcpy(port_name, "default");
        port_name_flag = TRUE;
    }

    if (*auth_type == knx_AuthType_SYMM_AUTH || *auth_type == knx_AuthType_None) {
        if (repo_id_flag) {
            LOG_E("\"-repoid\" option is not required for symmetric auth type.");
            return 1;
        }
        repo_id_flag = TRUE;
        if (curve_type_flag) {
            LOG_E("\"-curve\" option is not required for symmetric auth type.");
            return 1;
        }
        curve_type_flag = TRUE;
    }
    else if (*auth_type == knx_AuthType_SIGMA_I_Prover || *auth_type == knx_AuthType_SIGMA_I_Verifier) {
        if (key_id_flag) {
            LOG_E("\"-keyid\" option is not required for sigma auth type.");
            return 1;
        }
        key_id_flag = TRUE;
    }

    if (!(host_name_flag && port_name_flag && auth_type_flag && secure_tunnel_flag && key_id_flag && repo_id_flag &&
            curve_type_flag)) {
        if (!host_name_flag) {
            LOG_E("\"-smcom\" option is required for this operation. Refer usage for this command.");
        }
        if (!port_name_flag) {
            LOG_E("\"-port\" option is required for this operation. Refer usage for this command.");
        }
        if (!auth_type_flag) {
            LOG_E("\"-auth\" option is required for this operation. Refer usage for this command.");
        }
        if (!secure_tunnel_flag) {
            LOG_E("\"-sctunn\" option is required for this operation. Refer usage for this command.");
        }
        if (!key_id_flag) {
            LOG_E("\"-keyid\" option is required for this operation. Refer usage for this command.");
        }
        if (!repo_id_flag) {
            LOG_E("\"-repoid\" option is required for this operation. Refer usage for this command.");
        }
        if (!curve_type_flag) {
            LOG_E("\"-curve\" option is required for this operation. Refer usage for this command.");
        }
        return 1;
    }
    return 0;
}

// Creates a file which contains information related to connection context
void nxclitool_connect_to_se(int argc, const char *argv[])
{
    char host_name[MAX_HOST_NAME_LEN]        = {0};
    char port_name[MAX_PORT_NAME_LEN]        = {0};
    nx_auth_type_t auth_type                 = knx_AuthType_None;
    FILE *fh                                 = NULL;
    nx_secure_symm_type_t secure_tunnel_type = knx_SecureSymmType_None;

    // Parameters for Symmetric Auth
    uint8_t key_id    = 0;
    bool pcdcap2_flag = TRUE;

    // Parameters for Sigma Auth
    Nx_ECCurve_t curve_type                 = Nx_ECCurve_NA;
    sss_cipher_type_t host_cert_curve_type  = kSSS_CipherType_NONE;
    sss_cipher_type_t host_ephem_curve_type = kSSS_CipherType_NONE;
    auth_cache_type_t cache_type            = knx_AuthCache_Disabled;
    auth_compress_type_t compress_type      = knx_AuthCompress_Disabled;
    uint8_t se_cert_repo_id                 = 0;
    uint16_t cert_ac_map                    = 0;

    if ((0 == strcmp(argv[argc - 1], "-help"))) {
        nxclitool_show_command_help_connect();
        return;
    }

    if (nxclitool_fetch_connect_parameters(argc,
            argv,
            host_name,
            port_name,
            &auth_type,
            &secure_tunnel_type,
            &key_id,
            &se_cert_repo_id,
            &curve_type)) {
        nxclitool_show_command_help_connect();
        return;
    }

    switch (curve_type) {
    case Nx_ECCurve_NA:
        host_cert_curve_type  = kSSS_CipherType_NONE;
        host_ephem_curve_type = kSSS_CipherType_NONE;
        break;
    case Nx_ECCurve_NIST_P256:
        host_cert_curve_type  = kSSS_CipherType_EC_NIST_P;
        host_ephem_curve_type = kSSS_CipherType_EC_NIST_P;
        break;
    case Nx_ECCurve_Brainpool256:
        host_cert_curve_type  = kSSS_CipherType_EC_BRAINPOOL;
        host_ephem_curve_type = kSSS_CipherType_EC_BRAINPOOL;
        break;
    default:
        LOG_E("Invalid curve type");
        return;
    }

    fh = fopen(TEMP_FILE_NAME, "w");

    if (fh == NULL) {
        LOG_E("Error creating connection file. Try again");
        return;
    }

    // Storing all the parameter values in the file
    if (0 > (fprintf(fh,
                "%s %d %d %hhd %d %d %d %d %d %hhd %hd\n",
                host_name,
                auth_type,
                secure_tunnel_type,
                key_id,
                pcdcap2_flag,
                host_cert_curve_type,
                host_ephem_curve_type,
                cache_type,
                compress_type,
                se_cert_repo_id,
                cert_ac_map))) {
        LOG_E("Failed to write to the connection file");
    }
    if (0 > fprintf(fh, "%s", port_name)) {
        LOG_E("Failed to write to the connection file");
    }
    if (0 != fclose(fh)) {
        LOG_E("Failed to close the file handle!");
    }

    LOG_I("Connected to SA");
    return;
}

// Deletes the connection context file
void nxclitool_disconnect_with_se(int argc, const char *argv[])
{
    if (argc > 2) {
        LOG_W("\"disconnect\" does not require additional options. Ignoring the options...");
    }
    int status = remove(TEMP_FILE_NAME);
    if (status) {
        LOG_E("Error disconnecting. Maybe not connected...");
        return;
    }
    LOG_I("Disconnected");
}

// Returns 0 if OK, 1 if connection file is not found
int nxclitool_check_connection_and_get_ctx(nx_connect_ctx_t *pconn_ctx)
{
    int ret                                  = 1;
    FILE *fh                                 = NULL;
    char host_name[MAX_HOST_NAME_LEN]        = {0};
    char port_name[MAX_PORT_NAME_LEN]        = {0};
    nx_auth_type_t auth_type                 = knx_AuthType_None;
    nx_secure_symm_type_t secure_tunnel_type = knx_SecureSymmType_None;
    int fscanf_status                        = 0;
    char *ptr                                = NULL;

    // Parameters for Symmetric Auth
    uint8_t key_no    = 0;
    bool pcdcap2_flag = FALSE;
    int pcdcap2       = 0;

    // Parameters for Sigma Auth
    sss_cipher_type_t host_cert_curve_type;
    sss_cipher_type_t host_ephem_curve_type;
    auth_cache_type_t cache_type;
    auth_compress_type_t compress_type;
    uint8_t se_cert_repo_id;
    uint16_t cert_ac_map;

    fh = fopen(TEMP_FILE_NAME, "r");
    if (fh == NULL) {
        LOG_E("Connection file not found");
        ret = 1;
        goto cleanup;
    }

    fscanf_status = fscanf(fh,
        "%s %u %u %hhd %d %u %u %u %u %hhd %hd\n",
        host_name,
        &auth_type,
        &secure_tunnel_type,
        &key_no,
        &pcdcap2,
        &host_cert_curve_type,
        &host_ephem_curve_type,
        &cache_type,
        &compress_type,
        &se_cert_repo_id,
        &cert_ac_map);
    ptr           = fgets(port_name, MAX_PORT_NAME_LEN, fh);
    if (ptr == NULL) {
        LOG_E("Failed to read the port name from connection file!");
        if (0 != fclose(fh)) {
            LOG_E("Failed to close the file handle!");
            goto cleanup;
        }
        goto cleanup;
    }
    if (0 != fclose(fh)) {
        LOG_E("Failed to close the file handle!");
        goto cleanup;
    }
    ENSURE_OR_GO_CLEANUP(fscanf_status == 11);
    pcdcap2_flag = (pcdcap2 == 1);

    if (0 == strcmp(host_name, "pcsc")) {
        pconn_ctx->connType = kType_SE_Conn_Type_PCSC;
        if (0 == strcmp(port_name, "default")) {
            memset(port_name, 0, sizeof(port_name));
            strcpy(port_name, NXCLITOOL_SSS_BOOT_SSS_PCSC_READER_DEFAULT);
        }
        memcpy((void *)pconn_ctx->portName, port_name, sizeof(port_name));
    }
    else if (0 == strcmp(host_name, "vcom")) {
        pconn_ctx->connType = kType_SE_Conn_Type_VCOM;
        if (0 == strcmp(port_name, "default")) {
            memset(port_name, 0, sizeof(port_name));
            strcpy(port_name, NXCLITOOL_SSS_BOOT_SSS_COMPORT_DEFAULT);
        }
        memcpy((void *)pconn_ctx->portName, port_name, sizeof(port_name));
    }
    else if (0 == strcmp(host_name, "t1oi2c")) {
        pconn_ctx->connType = kType_SE_Conn_Type_T1oI2C;
        if (0 == strcmp(port_name, "default")) {
            memset(port_name, 0, sizeof(port_name));
            strcpy(port_name, NXCLITOOL_SSS_BOOT_SSS_I2C_PORT_DEFAULT);
        }
        memcpy((void *)pconn_ctx->portName, port_name, sizeof(port_name));
    }
    else {
        pconn_ctx->connType = kType_SE_Conn_Type_NONE;
        memcpy((void *)pconn_ctx->portName, port_name, sizeof(port_name));
    }

    switch (auth_type) {
    case knx_AuthType_None:
        break;
    case knx_AuthType_SYMM_AUTH:
        nx_init_conn_context_symm_auth(pconn_ctx, auth_type, secure_tunnel_type, key_no, pcdcap2_flag);
        break;
    case knx_AuthType_SIGMA_I_Prover:
    case knx_AuthType_SIGMA_I_Verifier:
        nx_init_conn_context_sigma_auth(pconn_ctx,
            auth_type,
            secure_tunnel_type,
            host_cert_curve_type,
            host_ephem_curve_type,
            cache_type,
            compress_type,
            se_cert_repo_id,
            cert_ac_map);
        break;
    default:
        LOG_E("Invalid Auth type passed");
        ret = 1;
        goto cleanup;
    }
    ret = 0;

cleanup:
    return ret;
}
