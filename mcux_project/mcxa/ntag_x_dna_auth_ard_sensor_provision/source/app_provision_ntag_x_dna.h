/* Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __APP_PROVISION_NTAG_X_DNA_H__
#define __APP_PROVISION_NTAG_X_DNA_H__

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <string.h>
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include "fsl_sss_nx_types.h"
#include "fsl_sss_nx_auth.h"
#include "fsl_sss_mbedtls_apis.h"
#include "nx_apdu.h"
#include "app_auth_ard.h"
#include "app_auth_device.h"
#include "app_ndef_util.h"
#include "app_ndef_record.h"

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/** @brief Default NDEF message URL used for SDM provisioning.
 *         Contains placeholder tokens for UID, read counter, and signature. */
#define NDEF_MSG \
    "ntag.nxp.com/xdna?m=04BE38BAD71E90&c=000025&temp=26.400&adc=081&s=604436C4206CF2E0103577C5107091C86FD85BB320AA2F57CEB708A2201B85F56E193D8330800EBD25C32CD65A0D922C975B65C2BB98944D78AB51D9677A0703"

/** @brief Size of the NDEF message buffer in bytes. */
#define NDEF_BUF_SIZE           256

/** @brief Offset in the NDEF buffer where the NDEF message starts (after 2-byte length field). */
#define NDEF_BUF_MSG_OFFSET     2

/** @brief Token string used to locate the VCUID mirror offset in the NDEF message. */
#define EX_SSS_SDM_VCUID_TOKEN          "?m="

/** @brief Token string used to locate the SDM read counter mirror offset in the NDEF message. */
#define EX_SSS_SDM_READ_CTR_TOKEN       "&c="

/** @brief Token string used to locate the SDM signature mirror offset in the NDEF message. */
#define EX_SSS_SDM_SIG_TOKEN            "&s="

/** @brief File number of the NDEF data file on the NTAG X DNA. */
#define EX_SSS_SDM_NDEF_FILE_NUMBER     0x02

/** @brief Total size of the NDEF file in bytes. */
#define EX_SSS_SDM_NDEF_FILE_SIZE       256

/** @brief File number of the Capability Container (CC) file on the NTAG X DNA. */
#define EX_SSS_SDM_CC_FILE_NUMBER               0x01

/** @brief Byte offset within the CC file for the read access condition field. */
#define EX_SSS_SDM_CC_FILE_READ_ACCESS_OFFSET   0x0E

/** @brief Length in bytes of the read access condition field in the CC file. */
#define EX_SSS_SDM_CC_FILE_READ_ACCESS_LENGTH   0x01

/** @brief Key ID used for AES-based SDM meta-read access condition. */
#define EX_SSS_SDM_AES_KEY_ID           Nx_SDMMetaRead_AccessCondition_Key_0x0

/** @brief New AES key version used during key update operations. */
#define EX_SSS_SDM_NEW_AES_KEY_VERSION  1

/** @brief Key ID used for ECC-based SDM file-read (signature) access condition. */
#define EX_SSS_SDM_ECC_KEY_ID           Nx_SDMFileRead_AccessCondition_Key_0x0

/** @brief Offset of the SDM encrypted data within the NDEF file.
 *  @note  Not used by this demo (encrypted PICC data is disabled). */
#define EX_SSS_SDM_ENC_OFFSET           0x60

/** @brief Length of the SDM encrypted data block.
 *  @note  Not used by this demo (encrypted PICC data is disabled). */
#define EX_SSS_SDM_ENC_LENGTH           0x20

/** @brief Certificate repository ID used to read the application certificate. */
#define EX_SSS_SDM_CERT_REPO_ID         0x00

/** @brief Maximum size in bytes of the application certificate buffer. */
#define EX_SSS_SDM_APP_CERT_BUF_SIZE    500

/** @brief Maximum size in bytes of the device UID buffer. */
#define EX_SSS_SDM_DEVICE_UID_BUF_SIZE  10

/* ************************************************************************** */
/* Function Prototypes                                                        */
/* ************************************************************************** */

/**
 * @brief   Provisions the NTAG X DNA tag for Secure Dynamic Messaging (SDM).
 *
 * @details This function performs the full provisioning sequence:
 *          - Opens a symmetric authenticated session.
 *          - Updates the ECC key policy to enable SDM signing.
 *          - Creates and writes an NDEF URI record with SDM mirror tokens.
 *          - Configures the NDEF file SDM settings (UID, read counter, signature offsets).
 *          - Updates the CC file to allow read access.
 *          - Configures GPIO2 in NfcPausefileOut mode.
 *          - Reads and logs the device UID and application certificate.
 *          - Closes the session.
 *
 * @return  kStatus_SSS_Success if all provisioning steps succeed.
 * @return  kStatus_SSS_Fail    if any step fails.
 */
sss_status_t provision_ntag_x_dna(void);

#endif /* __APP_PROVISION_NTAG_X_DNA_H__ */
