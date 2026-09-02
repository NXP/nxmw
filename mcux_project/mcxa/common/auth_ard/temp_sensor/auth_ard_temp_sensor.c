/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "auth_ard_temp_sensor.h"

/*******************************************************************************
 * Code
 ******************************************************************************/

status_t auth_ard_TempSensor_ReadValue(float *temp_value)
{
    status_t result = kStatus_Success;
    uint8_t data[2];
    int16_t raw;

    *temp_value = 0.0f;

    /* Read 2 bytes from the temperature register (MSB first) */
    result = I2C_ReadRegister(P3T1755_I2C_ADDR, P3T1755_TEMPERATURE_REG, &data[0], 2U);
    if (kStatus_Success == result)
    {
        /* Combine the two bytes into a 16-bit value and right-shift by 4 to
         * obtain the 12-bit two's complement raw temperature value.
         * The P3T1755 stores the temperature in the upper 12 bits of the
         * 16-bit register (bits [15:4])
         */
        raw = (int16_t)(((uint16_t)data[0] << 8U) | (uint16_t)data[1]);
        raw >>= 4;

        /* Convert raw value to degrees Celsius
         * Resolution: 1 LSB = 0.0625 °C (as per P3T1755 datasheet)
         */
        float tempCelsius = (float)raw * 0.0625f;

        /* Round to one decimal digit: multiply by 10, round to nearest integer, then divide by 10 */
        *temp_value = (float)((int32_t)(tempCelsius * 10.0f + (tempCelsius >= 0.0f ? 0.5f : -0.5f))) / 10.0f;
    }

    return result;
}
