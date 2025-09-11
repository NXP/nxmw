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
#include "ex_sdm_ver_uid_rctr_sig.h"
#include "ex_sdm_util.h"

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
    sss_status_t status                                   = kStatus_SSS_Fail;
    smStatus_t sm_status                                  = SM_NOT_OK;
    sss_nx_session_t *pSession                            = NULL;
    int ret                                               = -1;
    uint8_t fileNo                                        = EX_SSS_SDM_NDEF_FILE_NUMBER;
    uint8_t data[EX_SSS_SDM_NDEF_FILE_SIZE * 2]           = {0};
    size_t dataLen                                        = sizeof(data);
    uint8_t plainVCUID[EX_SSS_SDM_7BYTE_VCUID_LENGTH]     = {0};
    size_t plainVCUIDLen                                  = sizeof(plainVCUID);
    uint8_t plainSDMReadctr[EX_SSS_SDM_SDMREADCTR_LENGTH] = {0};
    size_t plainSDMReadctrLen                             = sizeof(plainSDMReadctr);
    size_t sdmReadCtrOffsetInPiccData                     = 0;
    uint32_t seSDMCtr                                     = 0;
    uint32_t repo_id                                      = 0x00;
    NX_CERTIFICATE_LEVEL_t cert_level                     = NX_CERTIFICATE_LEVEL_LEAF;
    Nx_CommMode_t known_comm_mode                         = Nx_CommMode_NA;
    uint8_t leafCertPublicKey[72]                         = {0};
    size_t leafCertPublicKeylen                           = sizeof(leafCertPublicKey);
    uint8_t certificate[NX_MAX_CERTIFICATE_SIZE]          = {0};
    uint8_t *pcertificate                                 = certificate;
    size_t certificateLen                                 = sizeof(certificate);
    size_t rdDataoff                                      = 0;
    size_t rdDataLen                                      = 0;
    ex_sss_boot_ctx_t ex_sdm_ver_uid_rctr_sig_ctx         = {0};
    ex_sss_boot_ctx_t *pCtx2                              = &ex_sdm_ver_uid_rctr_sig_ctx;
    nx_connect_ctx_t *pConnectCtx2                        = NULL;
    sss_session_t *pPfSession2                            = NULL;
    pPfSession2                                           = &pCtx2->session;
    pConnectCtx2                                          = &pCtx2->nx_open_ctx;

    if (pCtx == NULL) {
        LOG_E("Invalid Parameter!");
        goto exit;
    }

    pSession = (sss_nx_session_t *)&pCtx->session;

    //1. Read App.Leaf.Certificate
    sm_status =
        nx_ReadCertRepo_Cert(&pSession->s_ctx, repo_id, cert_level, pcertificate, &certificateLen, known_comm_mode);
    if (sm_status != SM_OK) {
        LOG_E("Failed to fetch certificate from repository at ID 0x%X", repo_id);
        status = kStatus_SSS_Fail;
        goto exit;
    }

    //2. Extract Public Key from AppLeafCert
    //strip away first 5 bytes (7F 21 82 01    6A)
    LOG_MAU8_D("Retrieved Leaf Certificate", pcertificate + 5, certificateLen - 5);
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
    //Init host session
    ex_sss_boot_open_host_session(pCtx2);
    LOG_I("SDM verification.");

    //4. Read NDEF file
    //4.1.  (first 2 bytes as NFC Forum device would) - trigger generation of SDM
    uint8_t tmplen[2] = {0};
    size_t tmplenLen  = sizeof(tmplen);
    rdDataLen         = 0x02;
    sm_status         = nx_ReadData(&((sss_nx_session_t *)pPfSession2)->s_ctx,
        fileNo,
        rdDataoff,
        rdDataLen,
        &tmplen[0],
        &tmplenLen,
        Nx_CommMode_NA);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    sm_status = SM_NOT_OK;
    LOG_MAU8_I("Read NDEF File (Length bytes only)", tmplen, tmplenLen);
    rdDataoff = rdDataLen;

    //4.2.  Rest of NDEF file - trigger generation of SDM
    sm_status = nx_ReadData(
        &((sss_nx_session_t *)pPfSession2)->s_ctx, fileNo, rdDataoff, tmplen[1], &data[0], &dataLen, Nx_CommMode_NA);
    ENSURE_OR_GO_EXIT(SM_OK == sm_status);
    sm_status = SM_NOT_OK;
    LOG_MAU8_I("Read NDEF File (Rest of bytes)", data, dataLen);
    LOG_I("NDEF URL %s \n\r", &data[3]);
    // 6. extract DynamicData
    // PICC data
    ret = sdm_ascii_to_hex(
        &(data[EX_SSS_SDM_VCUIDOffset - rdDataoff]), EX_SSS_SDM_ASCII_7BYTE_VCUID_LENGTH, plainVCUID, &plainVCUIDLen);
    ENSURE_OR_GO_EXIT(0 == ret);
    ENSURE_OR_GO_EXIT(plainVCUIDLen == EX_SSS_SDM_7BYTE_VCUID_LENGTH);

    LOG_MAU8_I("plain VCUID ", plainVCUID, EX_SSS_SDM_7BYTE_VCUID_LENGTH);

    ret = sdm_ascii_to_hex(&(data[EX_SSS_SDM_SDMREADCTROffset - rdDataoff]),
        EX_SSS_SDM_ASCII_SDMREADCTR_LENGTH,
        plainSDMReadctr,
        &plainSDMReadctrLen);
    ENSURE_OR_GO_EXIT(plainSDMReadctrLen == EX_SSS_SDM_SDMREADCTR_LENGTH);
    seSDMCtr = ((plainSDMReadctr[sdmReadCtrOffsetInPiccData + 0] << 16) |
                (plainSDMReadctr[sdmReadCtrOffsetInPiccData + 1] << 8) |
                (plainSDMReadctr[sdmReadCtrOffsetInPiccData + 2] << 0));
    LOG_I("SDMRead Counter 0x%06X. ", seSDMCtr);

    //7. Verify SIGSDM
    LOG_I("Verify Signature @0x%x(Length 0x%x) with data @0x%x(Length 0x%x))",
        EX_SSS_SDM_SDMMACOffset,
        EX_SSS_SDM_SDMSignatureLength,
        EX_SSS_SDM_SDMMACInputOffset,
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset);

    status = sdm_verify_data_signature(pCtx2,
        &data[EX_SSS_SDM_SDMMACInputOffset - rdDataoff],
        EX_SSS_SDM_SDMMACOffset - EX_SSS_SDM_SDMMACInputOffset,
        leafCertPublicKey,
        leafCertPublicKeylen,
        &data[(EX_SSS_SDM_SDMMACOffset - rdDataoff)],
        EX_SSS_SDM_SDMSignatureLength);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

exit:
    ex_sss_session_close(pCtx2);
    if (kStatus_SSS_Success == status) {
        LOG_I("ex_sdm_ver_uid_rctr_sig Example Success !!!...");
    }
    else {
        LOG_I("ex_sdm_ver_uid_rctr_sig Example Failed !!!...");
    }
    return status;
}