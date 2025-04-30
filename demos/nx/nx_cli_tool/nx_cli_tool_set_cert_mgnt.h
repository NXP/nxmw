/*
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

void nxclitool_show_command_help_set_cert_mgnt()
{
    printf("\nUSAGE: nxclitool set-cert_mgnt\n");
    printf("\n");
    printf("\t\t  leafcachesize\n");
    printf("\t\t  intermcachesize\n");
    printf("\t\t  featureselection\n");
    printf("\t\t  wcomm\n");
    printf("\t\t  waccess\n");
    printf("\n");
}

sss_status_t nxclitool_set_cert_mgnt(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status           = kStatus_SSS_Fail;
    smStatus_t sm_status          = SM_NOT_OK;
    sss_nx_session_t *pSession    = NULL;
    int i                         = 0;
    uint8_t rspleafcachesize      = 0;
    uint8_t rspintermcachesize    = 0;
    uint8_t rspfeatureselection   = 0;
    uint8_t rspacmanagecertrepo   = 0;
    uint8_t leafcachesize         = 0;
    uint8_t intermcachesize       = 0;
    uint8_t featureselection      = 0;
    uint8_t acmanagecertrepo      = 0;
    bool leafcachesize_flag       = FALSE;
    bool intermcachesize_flag     = FALSE;
    bool featureselection_flag    = FALSE;
    bool mngcertrepo_wcomm_flag   = FALSE;
    bool mngcertrepo_waccess_flag = FALSE;

    Nx_CommMode_t write_comm_mode          = Nx_CommMode_NA;
    Nx_AccessCondition_t write_access_cond = Nx_AccessCondition_Free_Access;

    ENSURE_OR_GO_EXIT(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    uint32_t temp_u32_holder = 0;

    if (i >= argc) {
        LOG_E("No options provided. Check usage below");
        return 1;
    }

    while (i < argc) {
        if (0 == strcmp(argv[i], "-leafcachesize")) {
            if (leafcachesize_flag != TRUE) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                leafcachesize_flag = TRUE;
                status             = nxclitool_get_uint32_from_hex_text(argv[i], &temp_u32_holder);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                ENSURE_OR_RETURN_ON_ERROR(temp_u32_holder <= UINT8_MAX, 1);
                leafcachesize = (uint8_t)temp_u32_holder;
                i++;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-intermcachesize")) {
            if (intermcachesize_flag != TRUE) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                intermcachesize_flag = TRUE;
                status               = nxclitool_get_uint32_from_hex_text(argv[i], &temp_u32_holder);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                ENSURE_OR_RETURN_ON_ERROR(temp_u32_holder <= UINT8_MAX, 1);
                intermcachesize = (uint8_t)temp_u32_holder;
                i++;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-featureselection")) {
            if (featureselection_flag != TRUE) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                featureselection_flag = TRUE;
                status                = nxclitool_get_uint32_from_hex_text(argv[i], &temp_u32_holder);
                ENSURE_OR_RETURN_ON_ERROR(status == kStatus_SSS_Success, 1);
                ENSURE_OR_RETURN_ON_ERROR(temp_u32_holder <= UINT8_MAX, 1);
                featureselection = (uint16_t)temp_u32_holder;
                i++;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-wcomm")) {
            if (mngcertrepo_wcomm_flag != TRUE) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                mngcertrepo_wcomm_flag = TRUE;
                if (nxclitool_get_comm_mode((char *)argv[i], &write_comm_mode)) {
                    LOG_E("Invalid parameter for \"-wcomm\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-wcomm\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else if (0 == strcmp(argv[i], "-waccess")) {
            if (mngcertrepo_waccess_flag != TRUE) {
                i++;
                CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
                mngcertrepo_waccess_flag = TRUE;
                if (nxclitool_get_access_cond((char *)argv[i], &write_access_cond)) {
                    LOG_E("Invalid parameter for \"-waccess\". Check usage below");
                    return 1;
                }
                i++;
            }
            else {
                LOG_E("\"-waccess\" is not required for this operation. Check usage below");
                return 1;
            }
            continue;
        }
        else {
            CHECK_INDEX_VALIDITY_OR_RETURN_ERROR(i, argc);
            LOG_W("Ignoring the unrecognised option \"%s\" for this command", argv[i]);
            i++;
        }
    }

    sm_status = nx_GetConfig_CertMgmt(
        &pSession->s_ctx, &rspleafcachesize, &rspintermcachesize, &rspfeatureselection, &rspacmanagecertrepo);
    ENSURE_OR_GO_EXIT(sm_status == SM_OK);

    if (leafcachesize_flag == FALSE) {
        leafcachesize = rspleafcachesize;
    }
    if (intermcachesize_flag == FALSE) {
        intermcachesize = rspintermcachesize;
    }
    if (featureselection_flag == FALSE) {
        featureselection = rspfeatureselection;
    }
    else {
        featureselection = (featureselection & 0x01) | (rspfeatureselection & 0xFE);
    }
    if (mngcertrepo_wcomm_flag == FALSE) {
        acmanagecertrepo |= (rspacmanagecertrepo & 0x30);
    }
    else {
        acmanagecertrepo |= ((write_comm_mode) << 4);
    }
    if (mngcertrepo_waccess_flag == FALSE) {
        acmanagecertrepo |= (rspacmanagecertrepo & 0x0F);
    }
    else {
        acmanagecertrepo |= write_access_cond;
    }

    sm_status =
        nx_SetConfig_CertMgmt(&pSession->s_ctx, leafcachesize, intermcachesize, featureselection, acmanagecertrepo);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);

    printf("\n");
    LOG_I("Cert Mgnt :");

    status = kStatus_SSS_Success;

exit:
    return status;
}