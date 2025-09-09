/*
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

void nxclitool_show_command_help_i2c_mgnt()
{
    printf("\nUSAGE: nxclitool set-i2c_mgnt\n");
    printf("\n");
    printf("\t\t  i2csupport\n");
    printf("\t\t  i2caddr\n");
    printf("\t\t  protocoloptions\n");
    printf("\n");
}

sss_status_t nxclitool_set_i2c_mgnt(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status         = kStatus_SSS_Fail;
    smStatus_t sm_status        = SM_NOT_OK;
    sss_nx_session_t *pSession  = NULL;
    int i                       = 0;
    uint8_t rspi2cSupport       = 0;
    uint8_t rspi2cAddr          = 0;
    uint16_t rspprotocolOptions = 0;

    uint8_t i2cSupport       = 0;
    uint8_t i2cAddr          = 0;
    uint16_t protocolOptions = 0;

    bool i2c_support_flag      = FALSE;
    bool i2c_addr_flag         = FALSE;
    bool protocol_options_flag = FALSE;

    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    uint32_t temp_u32_holder = 0;

    if (i >= argc) {
        LOG_E("No options provided. Check usage below");
        return 1;
    }

    while (i < argc) {
        if (0 == strcmp(argv[i], "-i2csupport")) {
            if (i2c_support_flag != TRUE) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                i2c_support_flag = TRUE;
                status           = nxclitool_get_uint32_from_hex_text(argv[i], &temp_u32_holder);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                ENSURE_OR_RETURN_ON_ERROR(temp_u32_holder <= UINT8_MAX, 1);
                i2cSupport = (uint8_t)temp_u32_holder;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-i2caddr")) {
            if (i2c_addr_flag != TRUE) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                i2c_addr_flag = TRUE;
                status        = nxclitool_get_uint32_from_hex_text(argv[i], &temp_u32_holder);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                ENSURE_OR_RETURN_ON_ERROR(temp_u32_holder <= UINT8_MAX, 1);
                i2cAddr = (uint8_t)temp_u32_holder;
                i++;
            }
        }
        else if (0 == strcmp(argv[i], "-protocoloptions")) {
            if (protocol_options_flag != TRUE) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                protocol_options_flag = TRUE;
                status                = nxclitool_get_uint32_from_hex_text(argv[i], &temp_u32_holder);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                ENSURE_OR_RETURN_ON_ERROR(temp_u32_holder <= UINT16_MAX, 1);
                protocolOptions = (uint16_t)temp_u32_holder;
                i++;
            }
        }
        else {
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            LOG_W("Ignoring the unrecognised option \"%s\" for this command", argv[i]);
            i++;
        }
    }

    sm_status = nx_GetConfig_I2CMgmt(&pSession->s_ctx, &rspi2cSupport, &rspi2cAddr, &rspprotocolOptions);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    if (i2c_support_flag == FALSE) {
        i2cSupport = rspi2cSupport;
    }
    if (i2c_addr_flag == FALSE) {
        i2cAddr = rspi2cAddr;
    }
    if (protocol_options_flag == FALSE) {
        protocolOptions = rspprotocolOptions;
    }

    sm_status = nx_SetConfig_I2CMgmt(&pSession->s_ctx, i2cSupport, i2cAddr, protocolOptions);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);

    printf("\n");
    LOG_I("I2C Mgnt :");

    status = kStatus_SSS_Success;

exit:
    return status;
}