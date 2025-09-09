/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "nx_apdu.h"
#include "ex_sdm_util.h"
#include "ex_sdm_ver_encpicc_sig.h"
static ex_sss_boot_ctx_t gex_sss_boot_ctx = {0};

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

/* ************************************************************************** */
/* Private Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                                         = kStatus_SSS_Fail;
    smStatus_t sm_status                                        = SM_NOT_OK;
    uint8_t fileNo                                              = EX_SSS_SDM_NDEF_FILE_NUMBER;
    uint8_t data[EX_SSS_SDM_NDEF_FILE_SIZE * 2]                 = {0};
    size_t dataLen                                              = sizeof(data);
    uint8_t plainPICCData[EX_SSS_SDM_PICCDATA_LENGTH]           = {0};
    size_t plainPICCDataLen                                     = sizeof(plainPICCData);
    uint8_t piccDataTag                                         = 0;
    uint8_t *pVCUID                                             = NULL;
    uint8_t plainVCUID[EX_SSS_SDM_VCUID_MAX_LENGTH_IN_PICCDATA] = {0};
    size_t plainVCUIDLen                                        = 0;
    size_t rdDataOff                                            = 0;
    size_t rdDataLen                                            = 0;
    uint32_t repo_id                                            = 0x00;
    NX_CERTIFICATE_LEVEL_t cert_level                           = NX_CERTIFICATE_LEVEL_LEAF;
    Nx_CommMode_t known_comm_mode                               = Nx_CommMode_NA;
    uint8_t leafCertPublicKey[72]                               = {0};
    size_t leafCertPublicKeylen                                 = sizeof(leafCertPublicKey);
    uint8_t certificate[NX_MAX_CERTIFICATE_SIZE]                = {0};
    uint8_t *pcertificate                                       = certificate;
    size_t certificateLen                                       = sizeof(certificate);
    ex_sss_boot_ctx_t ex_sdm_ver_encpicc_sig_ctx                = {0};
    ex_sss_boot_ctx_t *pCtx2                                    = &ex_sdm_ver_encpicc_sig_ctx;
    nx_connect_ctx_t *pConnectCtx2                              = NULL;
    sss_session_t *pPfSession2                                  = NULL;
    sss_nx_session_t *pSession                                  = NULL;
    pPfSession2                                                 = &pCtx2->session;
    pConnectCtx2                                                = &pCtx2->nx_open_ctx;

    if (pCtx == NULL) {
        LOG_E("Invalid Parameter!");
        goto exit;
    }

    pSession = (sss_nx_session_t *)&pCtx->session;

    //1. Read App.Leaf.Certificate
    sm_status =
        nx_ReadCertRepo_Cert(&pSession->s_ctx, repo_id, cert_level, certificate, &certificateLen, known_comm_mode);
    if (sm_status != SM_OK) {
        LOG_E("Failed to fetch certificate from repository at ID 0x%X", repo_id);
        status = kStatus_SSS_Fail;
        goto exit;
    }
    LOG_MAU8_D("Note: Application Certificate", pcertificate, certificateLen);

    //2. Extract Public Key from AppLeafCert
    //strip away first 5 bytes (7F 21 82 01    6A)
    parseCertGetPublicKey(pcertificate + 5, certificateLen - 5, leafCertPublicKey + 1, &leafCertPublicKeylen);
    if (leafCertPublicKeylen > COMPRESSED_KEY_SIZE) {
        /* Uncompressed key */
        leafCertPublicKey[0] = 0x04;
        leafCertPublicKeylen = leafCertPublicKeylen + 1;
    }
    else {
        /* Compressed key */
        LOG_E("Don't support compressed key");
        goto exit;
    }
    LOG_MAU8_I("Public Key from Application certificate: ", leafCertPublicKey, leafCertPublicKeylen);

    pConnectCtx2->connType = pCtx->nx_open_ctx.connType;
    pConnectCtx2->portName = pCtx->nx_open_ctx.portName;

    status = sss_session_open(pPfSession2, kType_SSS_SE_NX, 0, kSSS_ConnectionType_Plain, pConnectCtx2);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    LOG_I("Successfully opened Plain-session");
    //Setup Host session
    ex_sss_boot_open_host_session(pCtx2);

    LOG_I("SDM verification.");
    //4. Read NDEF file
    //4.1.  (first 2 bytes as NFC Forum device would) - trigger generation of SDM
    uint8_t tmplen[2] = {0};
    size_t tmplenLen  = sizeof(tmplen);
    rdDataLen         = 0x02;
    sm_status         = nx_ReadData(&((sss_nx_session_t *)pPfSession2)->s_ctx,
        fileNo,
        rdDataOff,
        rdDataLen,
        &tmplen[0],
        &tmplenLen,
        Nx_CommMode_NA);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    LOG_MAU8_I("Read NDEF File (Length bytes only)", tmplen, tmplenLen);
    sm_status = SM_NOT_OK;

    //4.2.  Rest of NDEF file - trigger generation of SDM
    rdDataOff = rdDataLen;
    sm_status = nx_ReadData(
        &((sss_nx_session_t *)pPfSession2)->s_ctx, fileNo, rdDataOff, tmplen[1], &data[0], &dataLen, Nx_CommMode_NA);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    LOG_MAU8_I("Read NDEF File (Rest of bytes)", data, dataLen);
    LOG_I("NDEF URL %s \n\r", &data[3]);
    sm_status = SM_NOT_OK;

    // 6. extract DynamicData
    LOG_I("Decrypt Encrypted PICCData @0x%x (Length 0x%x)", EX_SSS_SDM_PICCDATA_OFFSET, EX_SSS_SDM_PICCDATA_LENGTH);

    status = sdm_decrypt_picc_data(pCtx2,
        &(data[EX_SSS_SDM_PICCDATA_OFFSET - rdDataOff]),
        EX_SSS_SDM_PICCDATA_LENGTH,
        plainPICCData,
        &plainPICCDataLen);

    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
    ENSURE_OR_GO_EXIT(plainPICCDataLen == (EX_SSS_SDM_PICCDATA_LENGTH / 2));

    piccDataTag = plainPICCData[EX_SSS_SDM_TAG_OFFSET_IN_PICCDATA];
    if ((piccDataTag & EX_SSS_SDM_PICCDATA_TAG_VCUID_MASK) == EX_SSS_SDM_PICCDATA_TAG_VCUID_ENABLE) {
        if ((piccDataTag & EX_SSS_SDM_PICCDATA_TAG_VCUID_LENGTH_MASK) == EX_SSS_SDM_7BYTE_VCUID_LENGTH_IN_PICCDATA) {
            plainVCUIDLen = EX_SSS_SDM_7BYTE_VCUID_LENGTH_IN_PICCDATA;
        }
        else if ((piccDataTag & EX_SSS_SDM_PICCDATA_TAG_VCUID_LENGTH_MASK) ==
                 EX_SSS_SDM_10BYTE_VCUID_LENGTH_IN_PICCDATA) {
            plainVCUIDLen = EX_SSS_SDM_10BYTE_VCUID_LENGTH_IN_PICCDATA;
        }
        else {
            LOG_E("Invalid VCUID length");
            goto exit;
        }
    }

    pVCUID = &plainPICCData[EX_SSS_SDM_VCUID_OFFSET_IN_PICCDATA];
    memcpy(plainVCUID, pVCUID, plainVCUIDLen);
    LOG_MAU8_I("Get UID from PICCData.", plainVCUID, plainVCUIDLen);

    //Get dynamic data
    LOG_MAU8_D("Dynamic data in HEX:",
        &data[EX_SSS_SDM_SDMMACInputOffset - rdDataOff],
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset);

    //7. Verify SIGSDM
    LOG_I("Verify Signature @0x%x(Length 0x%x) with data @0x%x(Length 0x%x))",
        EX_SSS_SDM_SDMMACOffset,
        EX_SSS_SDM_SDMSignatureLength,
        EX_SSS_SDM_SDMMACInputOffset,
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset);

    status = sdm_verify_data_signature(pCtx2,
        &data[EX_SSS_SDM_SDMMACInputOffset - rdDataOff],
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset,
        leafCertPublicKey,
        leafCertPublicKeylen,
        &data[(EX_SSS_SDM_SDMMACOffset - rdDataOff)],
        EX_SSS_SDM_SDMSignatureLength);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
exit:

    ex_sss_session_close(pCtx2);

    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sdm_ver_encpicc_sig Example Success !!!...");
    }
    else {
        LOG_I("ex_sdm_ver_encpicc_sig Example Failed !!!...");
    }
    return status;
}