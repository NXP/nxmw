/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef TEMP_SENSOR_AUTH_ARD_TEMP_SENSOR_H_
#define TEMP_SENSOR_AUTH_ARD_TEMP_SENSOR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "auth_ard_i2c_common.h"

/* ************************************************************************** */
/* Macros                                                                     */
/* ************************************************************************** */

/*! @brief I2C address of the P3T1755 temperature sensor (A0=1, A1=1, A2=1) */
#define P3T1755_I2C_ADDR (0x4FU)

/*! @brief Temperature register address (read-only, 12-bit two's complement) */
#define P3T1755_TEMPERATURE_REG (0x00U)

/*! @brief Configuration register address (read/write) */
#define P3T1755_CONFIG_REG (0x01U)

/* ************************************************************************** */
/* API Functions                                                              */
/* ************************************************************************** */

/*!
 * @brief Reads the temperature value from the P3T1755 sensor.
 *
 * Reads the 12-bit two's complement temperature register over I2C and converts
 * the raw value to degrees Celsius. The resolution is 0.0625 °C per LSB.
 *
 * @param temp_value Pointer to a float where the temperature in degrees
 *                   Celsius will be stored
 *
 * @retval kStatus_Success Data was read successfully
 * @retval kStatus_LPI2C_Busy Another master is currently utilizing the bus
 * @retval kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte
 * @retval kStatus_LPI2C_FifoError FIFO under run or overrun
 * @retval kStatus_LPI2C_ArbitrationLost Arbitration lost error
 * @retval kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout
 */
status_t auth_ard_TempSensor_ReadValue(float *temp_value);

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif /* TEMP_SENSOR_AUTH_ARD_TEMP_SENSOR_H_ */
