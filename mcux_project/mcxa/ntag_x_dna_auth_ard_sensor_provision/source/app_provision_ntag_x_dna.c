/* Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "app_provision_ntag_x_dna.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */


/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */


/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */



/* ************************************************************************** */
/* Public Functions                                                           */
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
sss_status_t provision_ntag_x_dna(void)
{
	sss_status_t status         = kStatus_SSS_Fail;
	sss_status_t status_session = kStatus_SSS_Fail;
	smStatus_t sm_status        = SM_NOT_OK;
	sss_nx_session_t *pSession  = NULL;


	/* NDEF URI string containing SDM mirror tokens for UID, read counter, and signature */
	char uri_string[] = NDEF_MSG;

	/* SDM file configuration structure */
	nx_file_SDM_config_t sdmConfig = {0};

	/* File option byte for NDEF file settings */
	uint8_t fileOption = 0x00;

	/* Buffer for the full NDEF file content (2-byte length field + NDEF message) */
	uint8_t t4t_ndef[EX_SSS_SDM_NDEF_FILE_SIZE] = {0x00};

	/* Buffer for the CC file write (1 byte: read access condition set to R/W = 0x00) */
	uint8_t t4t_cc[EX_SSS_SDM_CC_FILE_READ_ACCESS_LENGTH] = {0x00};

	/* Offsets of SDM mirror fields within the NDEF file */
	uint32_t ndef_uid_offset      = 0;
	uint32_t ndef_read_ctr_offset = 0;
	uint32_t ndef_sign_offset     = 0;

	/* Length of the constructed NDEF RTD URI record */
	uint16_t ndefRtdUriRecordLen = 0;

	/* GPIO configuration structure for NfcPausefileOut mode */
	Nx_gpio_config_t gpioConfig = {0};

	/* Device UID buffer and length */
	uint8_t deviceUID[EX_SSS_SDM_DEVICE_UID_BUF_SIZE] = {0};
	size_t deviceUID_Length = sizeof(deviceUID);

	/* Application certificate buffer and length */
	uint8_t appCert[EX_SSS_SDM_APP_CERT_BUF_SIZE] = {0};
	size_t appCert_Length = sizeof(appCert);

	/* ------------------------------------------------------------------ */
	/* Step 1: Open a symmetric authenticated session                     */
	/* ------------------------------------------------------------------ */
	status_session = nx_auth_symmetric_session_open(&pSession, false);
	if (kStatus_SSS_Success != status_session) {
		LOG_E("Failed to open symmetric session");
		goto cleanup;
	}

	/* ------------------------------------------------------------------ */
	/* Step 2: Update ECC key policy to enable ECC-based SDM signing       */
	/* ------------------------------------------------------------------ */
	LOG_I("Update the KeyPolicy of the NXP pre-provisioned application EC-key "
		  "to enable ECC-based Secure Dynamic Messaging");

	sm_status = nx_ManageKeyPair(&pSession->s_ctx,
		EX_SSS_SDM_ECC_KEY_ID,
		Nx_MgtKeyPair_Act_Update_Meta,
		Nx_ECCurve_NIST_P256,
		NX_MGMT_KEYPAIR_POLICY_SDM_ENABLED |
		NX_MGMT_KEYPAIR_POLICY_ECC_SIGN_ENABLED |
		NX_MGMT_KEYPAIR_POLICY_SIGMAI_ENABLED,
		Nx_CommMode_FULL,
		Nx_AccessCondition_Auth_Required_0x0,
		0,    /* kucLimit: no usage limit */
		NULL, /* no additional key data */
		0x0,
		NULL,
		NULL,
		Nx_CommMode_NA);
	if (sm_status != SM_OK) {
		LOG_E("Failed to Manage Key Pair");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}

	/* ------------------------------------------------------------------ */
	/* Step 3: Build the NDEF URI record with SDM mirror token placeholders */
	/* ------------------------------------------------------------------ */
	ndefRtdUriRecordLen = createRtdUriRecord(
		NDEF_MB_TRUE,
		NDEF_ME_TRUE,
		uri_string,
		URI_ID_HTTPS,
		t4t_ndef,
		NDEF_BUF_MSG_OFFSET,
		EX_SSS_SDM_NDEF_FILE_SIZE);

	/* Write the 2-byte NDEF message length field at the start of the file buffer */
	t4t_ndef[0] = (uint8_t)((ndefRtdUriRecordLen & 0xFF00) >> 8);
	t4t_ndef[1] = (uint8_t)(ndefRtdUriRecordLen & 0x00FF);

	LOG_MAU8_I("NDEF File", t4t_ndef, EX_SSS_SDM_NDEF_FILE_SIZE);

	/* ------------------------------------------------------------------ */
	/* Step 4: Determine SDM mirror field offsets within the NDEF file     */
	/* ------------------------------------------------------------------ */

	/*
	 * Each offset is calculated from the token position within the NDEF message,
	 * plus the token size.
	 */
	ndef_uid_offset = getNdefDataOffset(
					  	  t4t_ndef, EX_SSS_SDM_NDEF_FILE_SIZE, EX_SSS_SDM_VCUID_TOKEN) +
						  strlen(EX_SSS_SDM_VCUID_TOKEN);

	ndef_read_ctr_offset = getNdefDataOffset(
							t4t_ndef, EX_SSS_SDM_NDEF_FILE_SIZE, EX_SSS_SDM_READ_CTR_TOKEN) +
							strlen(EX_SSS_SDM_READ_CTR_TOKEN);

	ndef_sign_offset = getNdefDataOffset(
						   t4t_ndef, EX_SSS_SDM_NDEF_FILE_SIZE, EX_SSS_SDM_SIG_TOKEN) +
						   strlen(EX_SSS_SDM_SIG_TOKEN);

	if (ndef_uid_offset == APP_NDEF_UTIL_TOKEN_PARSE_FAILED) {
		LOG_E("Failed to get VCUID NDEF file offset");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}
	LOG_I("NDEF file: SDM UID offset: %d (0x%02X)", ndef_uid_offset, ndef_uid_offset);

	if (ndef_read_ctr_offset == APP_NDEF_UTIL_TOKEN_PARSE_FAILED) {
		LOG_E("Failed to get read counter NDEF file offset");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}
	LOG_I("NDEF file: SDM read counter offset: %d (0x%02X)", ndef_read_ctr_offset, ndef_read_ctr_offset);

	if (ndef_sign_offset == APP_NDEF_UTIL_TOKEN_PARSE_FAILED) {
		LOG_E("Failed to get signature NDEF file offset");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}
	LOG_I("NDEF file: NDEF file signature offset: %d (0x%02X)", ndef_sign_offset, ndef_sign_offset);

	/* ------------------------------------------------------------------ */
	/* Step 5: Configure SDM settings and update the NDEF file settings    */
	/* ------------------------------------------------------------------ */
	LOG_I("Update NDEF-file settings (file ID = %d)", EX_SSS_SDM_NDEF_FILE_NUMBER);

	/*
	 * SDM options:
	 * - Mirror the VCUID (tag UID) in plain ASCII.
	 * - Mirror the SDM read counter in plain ASCII.
	 * - Use ASCII encoding for mirrored data.
	 */
	sdmConfig.sdmOption = NX_FILE_SDM_OPTIONS_VCUID |
						  NX_FILE_SDM_OPTIONS_SDMReadCtr |
						  NX_FILE_SDM_OPTIONS_ENCODING_ASCII;

	/* PICCData mirroring: plain (Free Access = 0xE), no encryption */
	sdmConfig.acSDMMetaRead = Nx_AccessCondition_Free_Access;

	/* Key used for ECC-based SDMSIG (signature) calculation */
	sdmConfig.acSDMFileRead2 = EX_SSS_SDM_ECC_KEY_ID;

	/* Key used for AES-based SDM meta-read */
	sdmConfig.acSDMFileRead = EX_SSS_SDM_AES_KEY_ID;

	/* Access condition for GetFileCounters command */
	sdmConfig.acSDMCtrRet = Nx_AccessCondition_Auth_Required_0x0;

	/* Mirror offsets within the NDEF file */
	sdmConfig.VCUIDOffset      = ndef_uid_offset;
	sdmConfig.SDMReadCtrOffset = ndef_read_ctr_offset;

	/*
	 * SDM MAC input starts at the UID mirror offset.
	 * SDM MAC (signature) is written at the signature mirror offset.
	 */
	sdmConfig.SDMMACInputOffset = ndef_uid_offset;
	sdmConfig.SDMMACOffset      = ndef_sign_offset;

	/*
	 * Encrypted PICC data and SDM ENC are not used in this demo.
	 * Set all related fields to zero.
	 */
	sdmConfig.PICCDataOffset = 0;
	sdmConfig.SDMENCOffset   = 0;
	sdmConfig.SDMENCLength   = 0;

	/* No read counter limit applied */
	sdmConfig.SDMReadCtrLimit = 0;

	/* Deferred SDM encryption is disabled for this demo */
	sdmConfig.deferSDMEncEnabled = false;
	sdmConfig.sdmDeferMethod     = NX_CONF_DEFERRAL_METHOD_NO_DEFERRAL;

	/* NDEF file option: SDM enabled, deferred mode disabled, plain communication */
	fileOption = NX_FILE_OPTION_SDM_ENABLED |
				 NX_FILE_OPTION_DEFERRED_DISABLED |
				 Nx_CommMode_Plain;

	sm_status = nx_ChangeFileSettings(&pSession->s_ctx,
		EX_SSS_SDM_NDEF_FILE_NUMBER,
		fileOption,
		Nx_AccessCondition_Free_Access, /* readAccessCondition      */
		Nx_AccessCondition_Free_Access, /* writeAccessCondition     */
		Nx_AccessCondition_Free_Access, /* readWriteAccessCondition */
		Nx_AccessCondition_Free_Access, /* changeAccessCondition    */
		&sdmConfig);
	if (sm_status != SM_OK) {
		LOG_E("Failed to set file for SDM read");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}

	/* ------------------------------------------------------------------ */
	/* Step 6: Write the NDEF file content (2-byte length + NDEF message)  */
	/* ------------------------------------------------------------------ */
	LOG_I("Update NDEF file content (LEN + NDEF message)");

	sm_status = nx_WriteData(
		&pSession->s_ctx,
		EX_SSS_SDM_NDEF_FILE_NUMBER,
		0,
		t4t_ndef,
		sizeof(t4t_ndef),
		Nx_CommMode_Plain);
	if (sm_status != SM_OK) {
		LOG_E("Failed to WriteData (NDEF file)");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}

	/* Log the URL portion of the NDEF message (skip 2-byte length + 4-byte NDEF header) */
	LOG_I("NDEF URL (without URI Identifier): %s \n\r", &t4t_ndef[6]);

	/* ------------------------------------------------------------------ */
	/* Step 7: Update CC file to grant R/W read access                     */
	/* ------------------------------------------------------------------ */
	/*
	 * Per NTAG X DNA static file system (ref. data sheet section 11.6):
	 * Write 0x00 to the read access byte in the CC file to change
	 * the access rights from Read-Only to Read/Write.
	 */
	LOG_I("CC-file: Change Read-Only access rights file to R/W.");

	sm_status = nx_WriteData(
		&pSession->s_ctx,
		EX_SSS_SDM_CC_FILE_NUMBER,
		EX_SSS_SDM_CC_FILE_READ_ACCESS_OFFSET,
		t4t_cc,
		EX_SSS_SDM_CC_FILE_READ_ACCESS_LENGTH,
		Nx_CommMode_Plain);
	if (sm_status != SM_OK) {
		LOG_E("Failed to WriteData (CC file)");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}

	/* ------------------------------------------------------------------ */
	/* Step 8: Configure GPIO2 in NfcPausefileOut mode                     */
	/* ------------------------------------------------------------------ */
	LOG_I("Configure GPIO2: Enable NfcPausefileOut.");

	sm_status = nx_GetConfig_GPIOMgmt(&pSession->s_ctx, &gpioConfig);
	if (sm_status != SM_OK) {
		LOG_E("Failed to get GPIO configuration");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}

	/*
	 * Configure GPIO2 to assert during NFC file access (NfcPausefileOut mode).
	 * This pauses the NFC field output while the NDEF file is being read,
	 * allowing the host MCU to update sensor data before the tag responds.
	 */
	gpioConfig.gpio2Mode                   = Nx_GPIOMgmtCfg_GPIOMode_NfcPausefileOut;
	gpioConfig.gpio2OutputNFCPauseFileNo   = EX_SSS_SDM_NDEF_FILE_NUMBER;
	gpioConfig.gpio2OutputNFCPauseOffset   = 0;
	gpioConfig.gpio2OutputNFCPauseLength   = 2;
	gpioConfig.gpio2OutputInitStateHigh    = Nx_GPIOOutput_Clear;
	gpioConfig.gpio2OutputCfg              = Nx_GPIOPadCfg_OutputCfg_GPIO_High_Speed_2;
	gpioConfig.acManage = (Nx_CommMode_Plain << NX_COMM_MODE_BIT_SHIFT) |
						  Nx_AccessCondition_Free_Access;
	gpioConfig.acRead   = (Nx_CommMode_Plain << NX_COMM_MODE_BIT_SHIFT) |
						  Nx_AccessCondition_Free_Access;

	sm_status = nx_SetConfig_GPIOMgmt(&pSession->s_ctx, gpioConfig);
	if (sm_status != SM_OK) {
		LOG_E("Failed to Configure GPIO");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}

	/* ------------------------------------------------------------------ */
	/* Step 9: Read and log the device UID for NTAG service registration   */
	/* ------------------------------------------------------------------ */
	LOG_I("==================================================================");
	LOG_I(" PLEASE provide the UID for NTAG service registration             ");
	LOG_I("==================================================================");

	sm_status = nx_GetCardUID(&pSession->s_ctx, deviceUID, &deviceUID_Length);
	if (sm_status != SM_OK) {
		LOG_E("Failed to get the Device UID");
		status = kStatus_SSS_Fail;
		goto cleanup;
	}
	LOG_MAU8_I("Device UID: 0x", deviceUID, deviceUID_Length);

	/* ------------------------------------------------------------------ */
	/* Step 10: Read and log the application certificate                   */
	/* ------------------------------------------------------------------ */
	LOG_I("==========================================================================");
	LOG_I(" PLEASE provide the application certificte. for NTAG service registration ");
	LOG_I("==========================================================================");

	sm_status = nx_ReadCertRepo_Cert(
		&pSession->s_ctx,
		EX_SSS_SDM_CERT_REPO_ID,
		NX_CERTIFICATE_LEVEL_LEAF,
		appCert,
		&appCert_Length,
		Nx_CommMode_NA);
	if (sm_status != SM_OK) {
		LOG_E("Failed to fetch the Application Certificate from repository at ID 0x%X",
			  EX_SSS_SDM_CERT_REPO_ID);
		status = kStatus_SSS_Fail;
		goto cleanup;
	}
	LOG_MAU8_I("Application certificate: ", appCert, appCert_Length);

	/* All steps completed successfully */
	status = kStatus_SSS_Success;

cleanup:
	/* ------------------------------------------------------------------ */
	/* Close the symmetric authenticated session                           */
	/* ------------------------------------------------------------------ */
	status_session = nx_auth_symmetric_session_close(pSession);
	if (kStatus_SSS_Success != status_session) {
		LOG_E("Failed to close symmetric session");
		status = kStatus_SSS_Fail;
	}

	return status;
}
