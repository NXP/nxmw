/*
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "app_ndef.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/** @brief Pointer to the active session with the NTAG X DNA device. */
static sss_nx_session_t *pSession = NULL;

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */


/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */


/**
 * @brief Retrieve sensor value offsets from NDEF file by searching for patterns.
 *
 * This function reads the NDEF file from the NTAG X DNA device via I2C,
 * searches for two specified patterns (tokens) within the file, and calculates
 * the file offsets where the corresponding sensor values should be written.
 *
 * The offsets returned point to the position immediately after each pattern,
 * where the actual sensor data values are stored.
 *
 * Since the NTAG X DNA device does not support concurrent I2C and NFC communication,
 * cold reset is triggered via the NFC interface to release the active interface assignment.
 *
 * @param[in]  pattern1          First pattern to search for (e.g., "&adc=").
 * @param[out] ndefFileOffset1   Pointer to store the offset for the first sensor value.
 * @param[in]  pattern2          Second pattern to search for (e.g., "&temp=").
 * @param[out] ndefFileOffset2   Pointer to store the offset for the second sensor value.
 *
 * @return int32_t
 *         - APP_NDEF_OK                     : Success, offsets retrieved.
 *         - APP_NDEF_NDEF_FILE_READ_FAILED  : Failed to read NDEF file.
 *         - APP_NDEF_FILE_EMPTY             : NDEF file is empty.
 *         - APP_NDEF_TOKEN_PARSE_FAILED     : One or both patterns not found or no valid token provided.
 */
int32_t app_getSensorValueNdefFileOffset(const char* pattern1, uint16_t* ndefFileOffset1,
								         const char* pattern2, uint16_t* ndefFileOffset2)
{
	sss_status_t status = kStatus_SSS_Fail;
	smStatus_t sm_status = SM_NOT_OK;
	int32_t return_status = APP_NDEF_OK;

	uint8_t ndef_file[NDEF_FILE_SIZE] = {0};
	size_t ndef_file_size = sizeof(ndef_file);

	int32_t offset1 = APP_NDEF_TOKEN_PARSE_FAILED;
	int32_t offset2 = APP_NDEF_TOKEN_PARSE_FAILED;

	if (pattern1 == NULL || ndefFileOffset1 == NULL ||
		pattern2 == NULL || ndefFileOffset2 == NULL)
	{
		return APP_NDEF_TOKEN_PARSE_FAILED;
	}

	*ndefFileOffset1 = 0;
	*ndefFileOffset2 = 0;

	/* Open a plain/symmetric or SIGMA-I session */
#if (defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE))
	status = nx_auth_plain_session_open(&pSession, false);
#elif (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH))
	status = nx_auth_symmetric_session_open(&pSession, false);
#elif ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
        (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)))
	status = nx_auth_sigma_i_session_open(&pSession, false);
#endif
	if (kStatus_SSS_Success != status)
	{
		return_status = APP_NDEF_NDEF_FILE_READ_FAILED;
		goto cleanup;
	}


	sm_status = nx_ReadData(&pSession->s_ctx,
							NDEF_FILE_ID,
							NDEF_FILE_OFFSET,
							ndef_file_size,
							ndef_file,
							&ndef_file_size,
							Nx_CommMode_Plain);
	if (SM_OK != sm_status)
	{
		return_status = APP_NDEF_NDEF_FILE_READ_FAILED;
		goto cleanup;
	}

	LOG_MAU8_I("Ndef File: ",ndef_file, ndef_file_size);

	 /* Check for empty NDEF file (NDEF LEN size is zero  */
	if(ndef_file[0] == 0 && ndef_file[1] == 0)
	{

		return_status =  APP_NDEF_FILE_EMPTY;
		goto cleanup;
	}

	/* Search for first pattern in NDEF file */
	offset1 = getNdefDataOffset(ndef_file, ndef_file_size, pattern1);

	/* Search for second pattern in NDEF file */
	offset2 = getNdefDataOffset(ndef_file, ndef_file_size, pattern2);

	 /* Check if either pattern was not found */
	if(offset1 == APP_NDEF_UTIL_TOKEN_PARSE_FAILED || offset2 == APP_NDEF_UTIL_TOKEN_PARSE_FAILED)
	{
		return_status = APP_NDEF_TOKEN_PARSE_FAILED;
		goto cleanup;
	}

	 /* Calculate actual data offsets  */
	*ndefFileOffset1 = offset1 + strlen(pattern1);
	*ndefFileOffset2 = offset2 + strlen(pattern2);

	/* Simultaneous communication over the I2C and NFC interfaces is not supported by the NTAG X DNA device.
	 * Perform a cold reset via the NFC interface to release the current interface assignment.
	 */
	SM_I2CColdReset(&pSession->s_ctx.conn_ctx);
cleanup:
	/* Close a plain/symmetric or SIGMA-I session */
#if (defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE))
	status = nx_auth_plain_session_close(pSession);
#elif (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH))
	status = nx_auth_symmetric_session_close(pSession);
#elif ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
	   (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)))
	status = nx_auth_sigma_i_session_close(pSession);
#endif
	if (kStatus_SSS_Success != status)
	{
		return_status = APP_NDEF_NDEF_FILE_READ_FAILED;
	}
	return return_status;
}


/**
 * @brief Update the NDEF file on NTAG X DNA with sensor data.
 *
 * Opens a plain or authenticated session with the NTAG X DNA device, writes the
 * temperature and slider values to the NDEF file at the specified offsets,
 * toggles GPIO2, and releases the NFC pause to allow NFC communication.
 *
 * @param[in] sliderValue                   Slider position value (0-100).
 * @param[in] sliderValueNdefFileOffset     Offset in NDEF file where slider value should be written.
 * @param[in] tempSensorValue               Temperature sensor reading in degrees Celsius.
 * @param[in] tempSensorValueNdefFileOffset Offset in NDEF file where temperature value should be written.
 *
 * @return sss_status_t
 *         - kStatus_SSS_Success : All operations succeeded.
 *         - kStatus_SSS_Fail    : One or more operations failed.
 */
sss_status_t app_updateNdefFile(uint8_t sliderValue, uint16_t sliderValueNdefFileOffset,
                    float tempSensorValue,  uint16_t tempSensorValueNdefFileOffset)
{
	uint8_t ndef_sensor_data[NDEF_FILE_SENSOR_VALUE_LEN] = {0};
	size_t ndef_sensor_data_len = sizeof(ndef_sensor_data);

	uint8_t ndef_temp_value_data[NDEF_FILE_TEMP_VALUE_LEN + 1] = {0};
	size_t ndef_temp_value_data_len = NDEF_FILE_TEMP_VALUE_LEN;

	sss_status_t status = kStatus_SSS_Fail;
	sss_status_t return_status = kStatus_SSS_Success;
	smStatus_t sm_status = SM_NOT_OK;


	/* Open a plain/symmetric or SIGMA-I session based on compile-time configuration */
#if (defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE))
	status = nx_auth_plain_session_open(&pSession, true);
#elif (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH))
	status = nx_auth_symmetric_session_open(&pSession, true);
#elif ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
        (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)))
	status = nx_auth_sigma_i_session_open(&pSession, true);
#endif
	if (kStatus_SSS_Success != status)
	{
		return kStatus_SSS_Fail;
	}

	/* Format temperature value as string (e.g., "23.5") */
	snprintf((char *)ndef_temp_value_data, sizeof(ndef_temp_value_data), "%2.1f", tempSensorValue);
    
	/* Write temperature value to NDEF file at specified offset */
	sm_status = nx_WriteData(&pSession->s_ctx,
							NDEF_FILE_ID,
							tempSensorValueNdefFileOffset,
							ndef_temp_value_data,
							ndef_temp_value_data_len,
							Nx_CommMode_NA);
	if (SM_OK != sm_status)
	{
		return_status = kStatus_SSS_Fail;
		goto cleanup;
	}

	/* Convert slider value to 3-digit ASCII string (e.g., 42 -> "042") */
	ndef_sensor_data[0] = (sliderValue / 100) + '0';
	ndef_sensor_data[1] = ((sliderValue % 100) / 10) + '0';
	ndef_sensor_data[2] = (sliderValue % 10) + '0';

	/* Write slider value to NDEF file at specified offset */
	sm_status = nx_WriteData(&pSession->s_ctx,
							NDEF_FILE_ID,
							sliderValueNdefFileOffset,
							ndef_sensor_data,
							ndef_sensor_data_len,
							Nx_CommMode_NA);
	if (SM_OK != sm_status)
	{
		return_status = kStatus_SSS_Fail;
		goto cleanup;
	}

	/* Toggle NTAG X DNA GPIO2 and release the NFC pause
	 * (stop WTX & transmit R-APDU via NFC interface) */
	sm_status = nx_ManageGPIO_Output(&pSession->s_ctx,
		Nx_GPIONo_2, /* NTAG X DNA GPIO2 */
		NX_MGMT_NFC_ACTION_RELEASE_NFC_PAUSE | Nx_GPIOOutput_Toggle, /* operation */
		NULL, /* If NFC Pause was triggered by ISOReadBinary/ReadData, no nfcPauseRespData needs to be provided */
		0,    /* nfcPauseRespDataLen */
		Nx_CommMode_NA);
	if (SM_OK != sm_status)
	{
		return_status = kStatus_SSS_Fail;
		goto cleanup;
	}

cleanup:
	/* Close a plain/symmetric or SIGMA-I session based on compile-time configuration  */
#if (defined(SSS_HAVE_AUTH_NONE) && (SSS_HAVE_AUTH_NONE))
	status = nx_auth_plain_session_close(pSession);
#elif (defined(SSS_HAVE_AUTH_SYMM_AUTH) && (SSS_HAVE_AUTH_SYMM_AUTH))
	status = nx_auth_symmetric_session_close(pSession);
#elif ((defined(SSS_HAVE_AUTH_SIGMA_I_VERIFIER) && (SSS_HAVE_AUTH_SIGMA_I_VERIFIER)) || \
	   (defined(SSS_HAVE_AUTH_SIGMA_I_PROVER) && (SSS_HAVE_AUTH_SIGMA_I_PROVER)))
	status = nx_auth_sigma_i_session_close(pSession);
#endif
	if (kStatus_SSS_Success != status)
	{
		return_status = kStatus_SSS_Fail;
	}

	return return_status;
}
