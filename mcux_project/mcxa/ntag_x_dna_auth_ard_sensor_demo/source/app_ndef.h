/*
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file app_ndef.h
 * @brief NTAG X DNA NDEF file management and device control.
 *
 * This header provides functions for managing the NTAG X DNA device,
 * including NDEF file updates for sensor data (temperature and slider values)
 * and device reset operations.
 */

#ifndef APP_NDEF_H_
#define APP_NDEF_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fsl_sss_api.h"
#include "fsl_sss_nx_auth.h"
#include "nx_apdu.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "platform.h"
#include "fsl_sss_nx_types.h"
#include "fsl_common_arm.h"
#include "frdm_mcxa153_adc.h"
#include "app_ndef_util.h"
#include "app_auth_device.h"
#include "app.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/** @brief NDEF file identifier in NTAG X DNA. */
#define NDEF_FILE_ID 2

/** @brief Starting offset for NDEF file operations. */
#define NDEF_FILE_OFFSET 0

/** @brief Total size of the NDEF file in bytes. */
#define NDEF_FILE_SIZE 256

///** @brief Default offset within NDEF file where temperature value is stored. */
#define NDEF_FILE_TEMP_VALUE_OFFSET 56

/** @brief Length of temperature value field in bytes (e.g., "23.5"). */
#define NDEF_FILE_TEMP_VALUE_LEN 4

/** @brief Token string used to locate temperature value in NDEF file. */
#define NDEF_FILE_TEMP_VALUE_TOKEN "&temp="

///** @brief Default offset within NDEF file where slider sensor value is stored. */
#define NDEF_FILE_SENSOR_VALUE_OFFSET 67

/** @brief Length of slider sensor value field in bytes (e.g., "042"). */
#define NDEF_FILE_SENSOR_VALUE_LEN 3

/** @brief Token string used to locate slider/ADC value in NDEF file. */
#define NDEF_FILE_SENSOR_VALUE_TOCKEN "&adc="

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/** @brief Operation completed successfully. */
#define APP_NDEF_OK                      0

/** @brief Failed to parse token/pattern in NDEF file. */
#define APP_NDEF_TOKEN_PARSE_FAILED     -1

/** @brief Failed to read NDEF file from device. */
#define APP_NDEF_NDEF_FILE_READ_FAILED  -2

/** @brief NDEF file is empty (first two bytes are zero). */
#define APP_NDEF_FILE_EMPTY             -3



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
 *
 * @note This function opens and closes a session with the NTAG X DNA device.
 */
int32_t app_getSensorValueNdefFileOffset(const char* pattern1, uint16_t* ndefFileOffset1,
										  const char* pattern2, uint16_t* ndefFileOffset2);


/**
 * @brief Update the NDEF file on NTAG X DNA with sensor data.
 *
 * Opens a plain or authenticated session with the NTAG X DNA device, writes the
 * temperature and slider values to the NDEF file at the specified offsets,
 * toggles GPIO2, and releases the NFC pause to allow NFC communication.
 *
 * @param[in] sliderValue                  Slider position value (0-100).
* @param[in] sliderValueNdefFileOffset    Offset in NDEF file where slider value should be written.
 * @param[in] tempSensorValue              Temperature sensor reading in degrees Celsius.
  * @param[in] tempSensorValueNdefFileOffset Offset in NDEF file where temperature value should be written.
  *
  * @return kStatus_SSS_Success if all operations succeed, kStatus_SSS_Fail otherwise.
 *
   *
 * @note If any operation fails, the function proceeds to cleanup and closes the session.
 *       The session type (plain, symmetric, or SIGMA-I) is determined by compile-time flags.
 */
sss_status_t  app_updateNdefFile(uint8_t sliderValue, uint16_t sliderValueNdefFileOffset, float tempSensorValue,
                     uint16_t tempSensorValueNdefFileOffset);

#endif /* APP_NDEF_H_  */
