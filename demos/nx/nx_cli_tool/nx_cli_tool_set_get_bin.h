/*
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

void nxclitool_show_command_help_create_bin()
{
    printf("\nUSAGE: nxclitool create-bin [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -bytes   File size in bytes\n");
    printf(
        "  -caccess, -raccess, -rwaccess, -waccess: Change, Read, Read-Write, Write Access Rights respectively. "
        "Accepted values:\n");
    printf("\t\t  0x00 to 0x0C\tAuth required\n");
    printf("\t\t  0x0D\t\tFree over I2C\n");
    printf("\t\t  0x0E\t\tFree Access\n");
    printf("\t\t  0x0F\t\tNo Access\n");
    printf("  -fcomm   File communication mode. Accepted values:\n");
    printf("\t\t  full\n");
    printf("\t\t  mac\n");
    printf("\t\t  na\n");
    printf("\t\t  plain\n");
    printf("  -id      File ID in hex format\n");
    printf("\n");
}

void nxclitool_show_command_help_setbin()
{
    printf("\nUSAGE: nxclitool setbin [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  [-bytes]\tNo. of bytes to store (optional). Default: No. of bytes from offset to EOF\n");
    printf("  -id\t\tFile ID in hex format\n");
    printf("  -in\t\tPath to the file to read\n");
    printf("  [-offset]\tOffset of data to read from and store at in SA (optional). Default: 0\n");
    printf("\n");
}

void nxclitool_show_command_help_getbin()
{
    printf("\nUSAGE: nxclitool getbin [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  [-bytes]\tNo. of bytes to store (optional). Default: No. of bytes from offset to EOF\n");
    printf("  -id\t\tFile ID in hex format\n");
    printf("  [-offset]\tOffset of data to read from and store at in SA (optional). Default: 0\n");
    printf("  [-out]\tStores the fetched data to a file on this path (optional)\n");
    printf("\n");
}

void nxclitool_show_command_help_list_fileid()
{
    printf("\nUSAGE: nxclitool list-fileid\n");
    printf("\n");
    printf("NOTE: list-fileid command does not require any additional arguments.\n");
    printf("\n");
}

int nxclitool_fetch_parameters_set_get_bin(int argc,
    const char *argv[],
    int i, // Starting index to fetch arguments
    uint8_t *file_id,
    uint8_t *read_access,
    uint8_t *write_access,
    uint8_t *read_write_access,
    uint8_t *change_access,
    uint8_t *comm_mode,
    size_t *offset,
    size_t *bytes,
    char file_in_path[],
    char file_out_path[],
    bool *file_out_flag)
{
    sss_status_t status = kStatus_SSS_Fail;

    bool file_id_flag           = (file_id == NULL);
    bool read_access_flag       = (read_access == NULL);
    bool write_access_flag      = (write_access == NULL);
    bool read_write_access_flag = (read_write_access == NULL);
    bool change_access_flag     = (change_access == NULL);
    bool comm_mode_flag         = (comm_mode == NULL);
    bool offset_flag            = (offset == NULL);
    bool bytes_flag             = (bytes == NULL);
    bool file_in_flag           = (file_in_path == NULL);

    uint32_t temp_u32_holder = 0;

    if (i >= argc) {
        LOG_E("No options provided. Check usage below");
        return 1;
    }

    while (i < argc) {
        if (0 == strcmp(argv[i], "-id")) {
            if (file_id != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                file_id_flag = TRUE;
                status       = nxclitool_get_uint32_from_hex_text(argv[i], &temp_u32_holder);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                ENSURE_OR_RETURN_ON_ERROR(temp_u32_holder <= UINT8_MAX, 1);
                *file_id = (uint8_t)temp_u32_holder;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-raccess")) {
            if (read_access != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                read_access_flag                       = TRUE;
                Nx_AccessCondition_t access_cond_local = Nx_AccessCondition_No_Access;
                if (nxclitool_get_access_cond((char *)argv[i], &access_cond_local)) {
                    LOG_E("Invalid parameter for \"-raccess\". Check usage below");
                    return 1;
                }
                *read_access = (uint8_t)access_cond_local;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-waccess")) {
            if (write_access != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                write_access_flag                      = TRUE;
                Nx_AccessCondition_t access_cond_local = Nx_AccessCondition_No_Access;
                if (nxclitool_get_access_cond((char *)argv[i], &access_cond_local)) {
                    LOG_E("Invalid parameter for \"-waccess\". Check usage below");
                    return 1;
                }
                *write_access = (uint8_t)access_cond_local;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-rwaccess")) {
            if (read_write_access != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                read_write_access_flag                 = TRUE;
                Nx_AccessCondition_t access_cond_local = Nx_AccessCondition_No_Access;
                if (nxclitool_get_access_cond((char *)argv[i], &access_cond_local)) {
                    LOG_E("Invalid parameter for \"-rwaccess\". Check usage below");
                    return 1;
                }
                *read_write_access = (uint8_t)access_cond_local;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-caccess")) {
            if (change_access != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                change_access_flag                     = TRUE;
                Nx_AccessCondition_t access_cond_local = Nx_AccessCondition_No_Access;
                if (nxclitool_get_access_cond((char *)argv[i], &access_cond_local)) {
                    LOG_E("Invalid parameter for \"-caccess\". Check usage below");
                    return 1;
                }
                *change_access = (uint8_t)access_cond_local;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-fcomm")) {
            if (comm_mode != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                comm_mode_flag                = TRUE;
                Nx_CommMode_t comm_mode_local = Nx_CommMode_NA;
                if (nxclitool_get_comm_mode((char *)argv[i], &comm_mode_local)) {
                    LOG_E("Invalid parameter for \"-fcomm\". Check usage below");
                    return 1;
                }
                *comm_mode = (uint8_t)comm_mode_local;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-offset")) {
            if (offset != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                offset_flag = TRUE;
                int temp    = atoi(argv[i]);
                if (temp < 0) {
                    LOG_E("Number of bytes cannot be negative");
                    return 1;
                }
                *offset = (size_t)temp;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-bytes")) {
            if (bytes != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                bytes_flag = TRUE;
                int temp   = atoi(argv[i]);
                if (temp < 0) {
                    LOG_E("Number of bytes cannot be negative");
                    return 1;
                }
                *bytes = (size_t)temp;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-in")) {
            if (file_in_path != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                strcpy(file_in_path, argv[i]);
                file_in_flag = TRUE;
                i++;
            }
            else {
                LOG_E("\"-in\" is not required for this operation. Check usage below");
                return 1;
            }
        }
        else if (0 == strcmp(argv[i], "-out")) {
            if (file_out_path != NULL) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                ENSURE_OR_RETURN_ON_ERROR(file_out_flag, 1);
                strcpy(file_out_path, argv[i]);
                *file_out_flag = TRUE;
                i++;
            }
            else {
                LOG_E("\"-out\" is not required for this operation. Check usage below");
                return 1;
            }
        }
        else {
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            LOG_W("Ignoring the unrecognised option \"%s\" for this command", argv[i]);
            i++;
        }
    }

    if (offset_flag == FALSE) {
        // In case offset is not passed in CLI, default value is zero
        *offset = 0;
    }
    if (bytes_flag == FALSE) {
        // In case bytes is not passed in CLI, default value is max of size_t and the caller function must
        // assign bytes based on file size
        *bytes = ULONG_MAX;
    }

    if (!(file_id_flag && read_access_flag && write_access_flag && read_write_access_flag && change_access_flag &&
            file_in_flag)) {
        if (!file_id_flag) {
            LOG_E("\"-id\" option is required for this operation. Refer usage for this command.");
        }
        if (!read_access_flag) {
            LOG_E("\"-raccess\" option is required for this operation. Refer usage for this command.");
        }
        if (!write_access_flag) {
            LOG_E("\"-waccess\" option is required for this operation. Refer usage for this command.");
        }
        if (!read_write_access_flag) {
            LOG_E("\"-rwaccess\" option is required for this operation. Refer usage for this command.");
        }
        if (!change_access_flag) {
            LOG_E("\"-caccess\" option is required for this operation. Refer usage for this command.");
        }
        if (!file_in_flag) {
            LOG_E("\"-in\" option is required for this operation. Refer usage for this command.");
        }
        return 1;
    }
    return 0;
}

sss_status_t nxclitool_create_bin(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status         = kStatus_SSS_Fail;
    sss_nx_session_t *pSession  = NULL;
    smStatus_t sm_status        = SM_NOT_OK;
    uint8_t fileNo              = 0;
    uint16_t isoFileID          = 0;
    size_t i                    = 0;
    uint8_t fileOption          = Nx_CommMode_NA;
    uint8_t fileReadAccess      = Nx_AccessCondition_No_Access;
    uint8_t fileWriteAccess     = Nx_AccessCondition_No_Access;
    uint8_t fileReadWriteAccess = Nx_AccessCondition_No_Access;
    uint8_t fileChangeAccess    = Nx_AccessCondition_No_Access;

    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;
    bool fileExists                       = false;
    size_t fileSize                       = 0;

    // Fetch arguments for creating file in SA
    if (nxclitool_fetch_parameters_set_get_bin(argc,
            argv,
            2,
            &fileNo,
            &fileReadAccess,
            &fileWriteAccess,
            &fileReadWriteAccess,
            &fileChangeAccess,
            &fileOption,
            NULL,
            &fileSize,
            NULL,
            NULL,
            NULL)) {
        LOG_E("Failed to fetch parameters for set bin command. Check usage below");
        nxclitool_show_command_help_setbin();
        status = kStatus_SSS_Fail;
        goto exit;
    }

    if (fileSize == ULONG_MAX) {
        LOG_E("\"-bytes\" option is required for this operation. Refer usage for this command.");
        LOG_E("Failed to fetch parameters for set bin command. Check usage below");
        nxclitool_show_command_help_setbin();
        status = kStatus_SSS_Fail;
        goto exit;
    }

    ENSURE_OR_GO_EXIT(fileSize < 1025);
    ENSURE_OR_GO_EXIT(fileNo < 32);

    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession  = (sss_nx_session_t *)&pCtx->session;
    isoFileID = fileNo + 1;

    pSeSession_t session_ctx = &((sss_nx_session_t *)pSession)->s_ctx;
    if (session_ctx->authType == knx_AuthType_SYMM_AUTH) {
        if (session_ctx->ctx.pdynSymmAuthCtx != NULL) {
            LOG_W("fileReadWriteAccess value is being overwritten for symmetric auth");
            fileReadWriteAccess = session_ctx->ctx.pdynSymmAuthCtx->keyNo;
        }
        else {
            LOG_E("Invalid symm auth context !!!");
        }
    }

    // Check if the file exists
    sm_status = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
    ENSURE_OR_GO_EXIT(fIDListLen <= NX_FILE_ID_LIST_SIZE);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    for (i = 0; i < fIDListLen; i++) {
        if (fileNo == fIDList[i]) {
            fileExists = true;
            break;
        }
    }

    // Create file if file is not present
    if (fileExists == false) {
        LOG_I("Creating standard data file inside SA");
        LOG_I("File ID: 0x%02X", fileNo);
        LOG_I("File size: %ld", fileSize);

        sm_status = nx_CreateStdDataFile(&((sss_nx_session_t *)pSession)->s_ctx,
            fileNo,
            isoFileID,
            fileOption,
            fileSize,
            fileReadAccess,
            fileWriteAccess,
            fileReadWriteAccess,
            fileChangeAccess);
        ENSURE_OR_GO_EXIT(sm_status == SM_OK);
        LOG_I("Standard Data File of size %d is successfully created at file ID 0x%02X", fileSize, fileNo);
    }
    else {
        LOG_E("Standard Data File already exists at file ID: 0x%02X", fileNo);
        goto exit;
    }
    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nxclitool_setbin(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status            = kStatus_SSS_Fail;
    sss_nx_session_t *pSession     = NULL;
    smStatus_t sm_status           = SM_NOT_OK;
    uint8_t fileNo                 = 0;
    uint16_t isoFileID             = 0;
    size_t i                       = 0;
    char fileIn[MAX_FILE_PATH_LEN] = {0}; // Path to input file
    FILE *fp                       = NULL;

    uint8_t writeData[MAX_FILE_DATA_BUF_SIZE] = {0};
    size_t writeOffset                        = 0;
    size_t bytesToWrite                       = 0;
    size_t writeDataLen                       = 0;

    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;
    bool fileExists                       = false;

    // Fetch arguments for setting file in SA
    if (nxclitool_fetch_parameters_set_get_bin(
            argc, argv, 2, &fileNo, NULL, NULL, NULL, NULL, NULL, &writeOffset, &bytesToWrite, fileIn, NULL, NULL)) {
        LOG_E("Failed to fetch parameters for set bin command. Check usage below");
        nxclitool_show_command_help_setbin();
        status = kStatus_SSS_Fail;
        goto exit;
    }

    ENSURE_OR_GO_EXIT(fileNo < 32);
    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession  = (sss_nx_session_t *)&pCtx->session;
    isoFileID = fileNo + 1;

    LOG_I("Using file at path \"%s\"", fileIn);
    if ((fp = fopen(fileIn, "rb")) != NULL) {
        writeDataLen = fread(writeData, sizeof(char), MAX_FILE_DATA_BUF_SIZE, fp);

        // Handle number of bytes to write if user does not specify "-bytes"
        if (bytesToWrite == ULONG_MAX) {
            bytesToWrite = writeDataLen;
        }

        if ((writeDataLen == 0) || ferror(fp)) { /* fread failed */
            LOG_E("Error reading data from file at path \"%s\"", fileIn);
            if (0 != fclose(fp)) {
                LOG_W("Failed to close the file handle");
            }
            goto exit;
        }

        if (0 != fclose(fp)) {
            LOG_W("Failed to close the file handle");
            goto exit;
        }

        if ((writeOffset > writeDataLen) || (bytesToWrite > writeDataLen)) {
            LOG_E("Invalid combination of offset and bytes to write. Target data is beyond the file data.");
            goto exit;
        }
    }
    else {
        LOG_E("Unable to open the file at path \"%s\"", fileIn);
        writeDataLen = 0;
        goto exit;
    }

    LOG_MAU8_D("Total data read from input file", writeData, writeDataLen);
    LOG_MAU8_I("Target data to be written", writeData, bytesToWrite);

    // Check if the file exists
    sm_status = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
    ENSURE_OR_GO_EXIT(fIDListLen <= NX_FILE_ID_LIST_SIZE);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    for (i = 0; i < fIDListLen; i++) {
        if (fileNo == fIDList[i]) {
            fileExists = true;
            break;
        }
    }

    // exit if file is not present
    if (fileExists == false) {
        LOG_E("Standard data file does not exists at file ID: 0x%02X", fileNo);
        goto exit;
    }

    // Write data to the file
    LOG_I("Writing data to the standard data file in SA");
    LOG_I("File ID: 0x%02X", fileNo);
    LOG_I("No. of bytes: %ld", bytesToWrite);
    LOG_I("Offset: %ld", writeOffset);

    sm_status = nx_WriteData(
        &((sss_nx_session_t *)pSession)->s_ctx, fileNo, writeOffset, writeData, bytesToWrite, Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        if (sm_status == SM_ERR_FILE_BOUNDARY) {
            LOG_E("Requested bytes are more than the file size present in SA");
        }
        goto exit;
    }
    LOG_I("File write successful !!!");

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nxclitool_getbin(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status             = kStatus_SSS_Fail;
    sss_nx_session_t *pSession      = NULL;
    smStatus_t sm_status            = SM_NOT_OK;
    uint8_t fileNo                  = 0;
    size_t i                        = 0;
    char fileOut[MAX_FILE_PATH_LEN] = {0};
    bool outFileFlag                = FALSE;
    size_t bytes_written            = 0;

    uint8_t readData[MAX_FILE_DATA_BUF_SIZE] = {0};
    size_t bytesToRead                       = 20;
    size_t readOffset                        = 0;

    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;
    bool fileExists                       = false;

    // Fetch arguments for reading file from SA
    if (nxclitool_fetch_parameters_set_get_bin(argc,
            argv,
            2,
            &fileNo,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &readOffset,
            &bytesToRead,
            NULL,
            fileOut,
            &outFileFlag)) {
        LOG_E("Failed to fetch parameters for get bin command. Check usage below");
        nxclitool_show_command_help_setbin();
        status = kStatus_SSS_Fail;
        goto exit;
    }
    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    // Check if the file exists
    sm_status = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
    ENSURE_OR_GO_EXIT(fIDListLen <= NX_FILE_ID_LIST_SIZE);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    for (i = 0; i < fIDListLen; i++) {
        if (fileNo == fIDList[i]) {
            fileExists = true;
            break;
        }
    }
    if (!fileExists) {
        LOG_E("Data file is not present at file ID 0x%02X", fileNo);
        goto exit;
    }

    // Handle number of bytes to write if user does not specify "-bytes"
    if (bytesToRead == ULONG_MAX) {
        // Dummy variables to get size of file from SA
        Nx_FILEType_t fileType;
        uint8_t fileOption;
        Nx_AccessCondition_t rAccess;
        Nx_AccessCondition_t wAccess;
        Nx_AccessCondition_t rwAccess;
        Nx_AccessCondition_t cAccess;
        nx_file_SDM_config_t sdmConfig;

        bytesToRead = 0;
        sm_status   = nx_GetFileSettings(&((sss_nx_session_t *)pSession)->s_ctx,
            fileNo,
            &fileType,
            &fileOption,
            &rAccess,
            &wAccess,
            &rwAccess,
            &cAccess,
            &bytesToRead,
            &sdmConfig);
        ENSURE_OR_GO_EXIT(sm_status == SM_OK);

        bytesToRead = bytesToRead - readOffset;
    }

    if (bytesToRead > MAX_FILE_DATA_BUF_SIZE) {
        LOG_E("Data buffer size insufficient to hold %d bytes. Max allowed length is %d",
            bytesToRead,
            MAX_FILE_DATA_BUF_SIZE);
        goto exit;
    }

    LOG_I("Reading data from the standard data file inside SA");
    LOG_I("File ID: 0x%02X", fileNo);
    LOG_I("No. of bytes: %ld", bytesToRead);
    LOG_I("Offset: %ld", readOffset);

    // Read data from file
    sm_status = nx_ReadData(&((sss_nx_session_t *)pSession)->s_ctx,
        fileNo,
        readOffset,
        bytesToRead,
        readData,
        &bytesToRead,
        Nx_CommMode_NA);
    if (sm_status != SM_OK) {
        if (sm_status == SM_ERR_FILE_BOUNDARY) {
            LOG_E("Requested data goes beyond the file size present in SA");
        }
        goto exit;
    }

    LOG_AU8_I(readData, bytesToRead);

    if (outFileFlag) {
        FILE *fh = fopen(fileOut, "wb");
        if (NULL == fh) {
            LOG_W("Unable to open a file to store the data");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        bytes_written = fwrite(readData, sizeof(uint8_t), bytesToRead, fh);
        if (bytes_written != bytesToRead) {
            LOG_W("Failed to write data into the file");
            if (0 != fclose(fh)) {
                LOG_W("Failed to close the file handle");
            }
            status = kStatus_SSS_Fail;
            goto exit;
        }
        else {
            LOG_I("Storing the fetched data in file \"%s\"", fileOut);
        }
        if (0 != fclose(fh)) {
            LOG_W("Failed to close the file handle");
            status = kStatus_SSS_Fail;
            goto exit;
        }
    }
    else {
        LOG_W("No file path provided. Data will not be saved in file system");
    }
    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nxclitool_list_fileid(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                   = kStatus_SSS_Fail;
    smStatus_t sm_status                  = SM_NOT_OK;
    sss_nx_session_t *pSession            = NULL;
    uint8_t fIDList[NX_FILE_ID_LIST_SIZE] = {0};
    size_t fIDListLen                     = 0;

    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    sm_status = nx_GetFileIDs(&((sss_nx_session_t *)pSession)->s_ctx, fIDList, &fIDListLen);
    ENSURE_OR_GO_EXIT(fIDListLen <= NX_FILE_ID_LIST_SIZE);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    LOG_MAU8_I("List of file IDs present inside SA", fIDList, fIDListLen);
    status = kStatus_SSS_Success;

exit:
    return status;
}