/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "nx_cli_tool_common.h"
#include "nx_cli_tool_connect.h"
#include "nx_cli_tool_rng.h"
#include "nx_cli_tool_keygen.h"
#include "nx_cli_tool_mng_crt_repo.h"
#include "nx_cli_tool_get_uid.h"
#include "nx_cli_tool_set_key.h"
#include "nx_cli_tool_get_ref_key.h"
#include "nx_cli_tool_set_get_bin.h"

/* ************************************************************************** */
/* Function Definitions                                                       */
/* ************************************************************************** */

// Checks command from command line and executes the respective function
void nxclitool_execute_command(int argc, const char *argv[])
{
    int ret                           = 1;
    sss_status_t status               = kStatus_SSS_Fail;
    nxclitool_sss_boot_ctx_t boot_ctx = {0};
    nx_connect_ctx_t conn_ctx         = {0};
    char port_name[MAX_PORT_NAME_LEN] = {0};
    size_t rng_bytes                  = 0;
    uint32_t key_id;
    Nx_ECCurve_t curve_type;
    char file_in_path[MAX_FILE_PATH_LEN] = {0};
    char file_out_path[MAX_FILE_PATH_LEN];
    bool file_out_flag              = FALSE;
    NXCLITOOL_OPERATION_t operation = NXCLITOOL_OPERATION_SIGN;

    conn_ctx.portName = port_name;

    // RNG
    if (0 == strcmp(argv[1], "rand")) {
        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_rng();
            return;
        }

        if (nxclitool_fetch_parameters(argc,
                argv,
                2,
                &rng_bytes,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL)) {
            nxclitool_show_command_help_rng();
            ret = 1;
            goto cleanup;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        if (!rng_bytes) {
            LOG_E("Bytes cannot be zero or alpha-numeric");
            nxclitool_show_command_help_rng();
            ret = 1;
            goto cleanup;
        }

        // Session open
        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_do_rng(&boot_ctx, &conn_ctx, rng_bytes);
    }

    // Generate Key
    else if (0 == strcmp(argv[1], "genkey")) {
        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_generate();
            return;
        }

        if (nxclitool_fetch_parameters(argc,
                argv,
                2,
                NULL,
                NULL,
                &key_id,
                &curve_type,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                file_out_path,
                &file_out_flag,
                NULL)) {
            nxclitool_show_command_help_generate();
            ret = 1;
            goto cleanup;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        // Session open
        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_do_generate_key(
            argc, argv, &boot_ctx, &conn_ctx, key_id, curve_type, file_out_path, file_out_flag);
    }

    // Create Certificate Repo
    else if (0 == strcmp(argv[1], "certrepo-create")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_crt_repo_create_cmd();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_crt_repo_create_cmd();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        // Session open
        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_crt_repo_create(argc, argv, &boot_ctx);
    }

    // Activate Certificate Repo
    else if (0 == strcmp(argv[1], "certrepo-activate")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_crt_repo_activate_cmd();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_crt_repo_activate_cmd();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_crt_repo_activate(argc, argv, &boot_ctx);
        ret    = 0;
    }

    // Load Key in Certificate Repo
    else if (0 == strcmp(argv[1], "certrepo-load-key")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_crt_repo_loadkey_cmd();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_crt_repo_loadkey_cmd();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_crt_repo_load_key(argc, argv, &boot_ctx);
    }

    // Read Certificate from Certificate Repo
    else if (0 == strcmp(argv[1], "certrepo-read-cert")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_crt_repo_read_crt_cmd();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_crt_repo_read_crt_cmd();
            goto cleanup;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_crt_repo_read_cert(argc, argv, &boot_ctx);
    }

    // Read Metadata from Certificate Repo
    else if (0 == strcmp(argv[1], "certrepo-read-metadata")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_crt_repo_read_metadata_cmd();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_crt_repo_read_metadata_cmd();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_crt_repo_read_metadata(argc, argv, &boot_ctx);
    }

    // Load Certificate or mapping in Certificate Repo
    else if ((0 == strcmp(argv[1], "certrepo-load-cert")) || (0 == strcmp(argv[1], "certrepo-load-mapping"))) {
        if ((argc < 3) || (0 == strcmp(argv[argc - 1], "-help"))) {
            if (0 == strcmp(argv[1], "certrepo-load-cert")) {
                nxclitool_show_command_help_crt_repo_load_cert_cmd();
            }
            else {
                nxclitool_show_command_help_crt_repo_load_mapping_cmd();
            }
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_crt_repo_load_cert_and_mapping(argc, argv, &boot_ctx);
    }

    // Reset Certificate Repo
    else if (0 == strcmp(argv[1], "certrepo-reset")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_crt_repo_reset_cmd();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_crt_repo_reset_cmd();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_crt_repo_reset(argc, argv, &boot_ctx);
    }

    // Get UID
    else if (0 == strcmp(argv[1], "get-uid")) {
        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_get_uid();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_get_uid(argc, argv, &boot_ctx);
    }

    // Set key
    else if (0 == strcmp(argv[1], "setkey")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_set_key();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_set_key();
            return;
        }

        if (nxclitool_fetch_parameters(argc,
                argv,
                2,
                NULL,
                NULL,
                &key_id,
                &curve_type,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                file_in_path,
                NULL,
                NULL,
                &operation)) {
            LOG_E("Failed to fetch parameters for set key command. Check usage below");
            nxclitool_show_command_help_set_key();
            goto cleanup;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_set_key(argc, argv, &boot_ctx, key_id, curve_type, operation, file_in_path);
    }

    // Get reference key
    else if (0 == strcmp(argv[1], "get-ref-key")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_get_ref_key();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_get_ref_key();
            return;
        }

        if (nxclitool_fetch_parameters(argc,
                argv,
                2,
                NULL,
                NULL,
                &key_id,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                file_in_path,
                file_out_path,
                &file_out_flag,
                NULL)) {
            LOG_E("Failed to fetch parameters for get reference key command. Check usage below");
            nxclitool_show_command_help_get_ref_key();
            goto cleanup;
        }

        // Session is not required for this operation as no need to communicate with SA
        status = nxclitool_get_ref_key(argc, argv, &boot_ctx, key_id, file_in_path, file_out_path, file_out_flag);
    }

    // Create a binary file in SA
    else if (0 == strcmp(argv[1], "create-bin")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_create_bin();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_create_bin();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = nxclitool_create_bin(argc, argv, &boot_ctx);
    }

    // Set data in a binary file in SA
    else if (0 == strcmp(argv[1], "setbin")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_setbin();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_setbin();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = nxclitool_setbin(argc, argv, &boot_ctx);
    }

    // Read a binary file in SA
    else if (0 == strcmp(argv[1], "getbin")) {
        if (argc < 3) {
            LOG_E("Too few arguments. Refer usage below");
            nxclitool_show_command_help_getbin();
            ret = 1;
            goto cleanup;
        }

        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_getbin();
            return;
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = nxclitool_getbin(argc, argv, &boot_ctx);
    }

    // List standard file IDs present in SA
    else if (0 == strcmp(argv[1], "list-fileid")) {
        if ((0 == strcmp(argv[argc - 1], "-help"))) {
            nxclitool_show_command_help_list_fileid();
            return;
        }

        if (argc > 2) {
            LOG_W("\"list-fileid\" does not need any arguments. Ignoring the arguments...");
        }

        ret = nxclitool_check_connection_and_get_ctx(&conn_ctx);
        if (ret) {
            LOG_E("Not connected. Connect to SA first");
            nxclitool_show_usage();
            goto cleanup;
        }

        status = nxclitool_do_session_open(&boot_ctx, &conn_ctx, conn_ctx.auth.authType);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);
        status = nxclitool_list_fileid(argc, argv, &boot_ctx);
    }

    // Invalid Command
    else {
        LOG_E("Invalid command. Refer usage below");
        nxclitool_show_usage();
    }

cleanup:
    if (kStatus_SSS_Success == status) {
        LOG_I("Operation successful!!");
    }
    else {
        LOG_E("Operation failed!!");
    }
    nxclitool_do_session_close_and_cleanup(&boot_ctx, &conn_ctx);
}

int main(int argc, const char *argv[])
{
    if (argc < 2) {
        nxclitool_show_usage();
        return 0;
    }
    if (0 == strcmp(argv[1], "connect")) {
        nxclitool_connect_to_se(argc, argv);
    }
    else if (0 == strcmp(argv[1], "disconnect")) {
        nxclitool_disconnect_with_se(argc, argv);
    }
    else if (0 == strcmp(argv[1], "-help")) {
        nxclitool_show_usage();
    }
    else {
        nxclitool_execute_command(argc, argv);
    }

    return 0;
}