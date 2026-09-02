/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef AUTH_ARD_I2C_COMMON_H_
#define AUTH_ARD_I2C_COMMON_H_

#include "fsl_debug_console.h"
#include "fsl_lpi2c.h"
#include "fsl_clock.h"
#include "fsl_common_arm.h"

/* ************************************************************************** */
/* Macros                                                                     */
/* ************************************************************************** */

/*! @brief Macro to check condition and jump to cleanup on failure */
#define AUTH_ARD_ENSURE_OR_GO_CLEANUP(CONDITION) \
    if (!(CONDITION)) {                          \
        goto cleanup;                            \
    }

/*! @brief I2C master peripheral base address */
#define AUTH_ARD_I2CM ((LPI2C_Type *)(LPI2C0_BASE))

/* ************************************************************************** */
/* API Functions                                                              */
/* ************************************************************************** */

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @brief Writes a single byte to a specific register of an I2C device.
 *
 * This function performs a blocking I2C write operation to write one byte
 * to a specified register address of an I2C device.
 *
 * @param deviceAddress The 7-bit I2C address of the target device
 * @param regAddress The register address within the device to write to
 * @param regValue The byte value to write to the specified register
 *
 * @retval kStatus_Success Data was written successfully
 * @retval kStatus_LPI2C_Busy Another master is currently utilizing the bus
 * @retval kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte
 * @retval kStatus_LPI2C_FifoError FIFO under run or overrun
 * @retval kStatus_LPI2C_ArbitrationLost Arbitration lost error
 * @retval kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout
 */
status_t I2C_WriteRegisterByte(uint8_t deviceAddress, uint32_t regAddress, uint8_t regValue);

/*!
 * @brief Writes data to a specific register of an I2C device.
 *
 * This function performs a blocking I2C write operation to write multiple bytes
 * to a specified register address of an I2C device.
 *
 * @param deviceAddress The 7-bit I2C address of the target device
 * @param regAddress The register address within the device to write to
 * @param regData Pointer to the data buffer to be written
 * @param dataSize Number of bytes to write from regData
 *
 * @retval kStatus_Success Data was written successfully
 * @retval kStatus_LPI2C_Busy Another master is currently utilizing the bus
 * @retval kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte
 * @retval kStatus_LPI2C_FifoError FIFO under run or overrun
 * @retval kStatus_LPI2C_ArbitrationLost Arbitration lost error
 * @retval kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout
 */
status_t I2C_WriteRegister(uint8_t deviceAddress, uint32_t regAddress, uint8_t *regData, size_t dataSize);

/*!
 * @brief Writes data to an I2C device without register address.
 *
 * This function performs a blocking I2C write operation to write data directly
 * to an I2C device without specifying a register address.
 *
 * @param deviceAddress The 7-bit I2C address of the target device
 * @param data Pointer to the data buffer to be written
 * @param dataSize Number of bytes to write from data
 *
 * @retval kStatus_Success Data was written successfully
 * @retval kStatus_LPI2C_Busy Another master is currently utilizing the bus
 * @retval kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte
 * @retval kStatus_LPI2C_FifoError FIFO under run or overrun
 * @retval kStatus_LPI2C_ArbitrationLost Arbitration lost error
 * @retval kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout
 */
status_t I2C_Write(uint8_t deviceAddress, uint8_t *data, size_t dataSize);

/*!
 * @brief Reads a single byte from a specific register of an I2C device.
 *
 * This function performs a blocking I2C read operation to read one byte
 * from a specified register address of an I2C device.
 *
 * @param deviceAddress The 7-bit I2C address of the target device
 * @param regAddress The register address within the device to read from
 * @param regValue Pointer to the buffer where the read data will be stored
 *
 * @retval kStatus_Success Data was read successfully
 * @retval kStatus_LPI2C_Busy Another master is currently utilizing the bus
 * @retval kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte
 * @retval kStatus_LPI2C_FifoError FIFO under run or overrun
 * @retval kStatus_LPI2C_ArbitrationLost Arbitration lost error
 * @retval kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout
 */
status_t I2C_ReadRegisterByte(uint8_t deviceAddress, uint32_t regAddress, uint8_t *regValue);

/*!
 * @brief Reads data from a specific register of an I2C device.
 *
 * This function performs a blocking I2C read operation to read multiple bytes
 * from a specified register address of an I2C device.
 *
 * @param deviceAddress The 7-bit I2C address of the target device
 * @param regAddress The register address within the device to read from
 * @param regData Pointer to the buffer where the read data will be stored
 * @param dataSize Number of bytes to read into regData
 *
 * @retval kStatus_Success Data was read successfully
 * @retval kStatus_LPI2C_Busy Another master is currently utilizing the bus
 * @retval kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte
 * @retval kStatus_LPI2C_FifoError FIFO under run or overrun
 * @retval kStatus_LPI2C_ArbitrationLost Arbitration lost error
 * @retval kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout
 */
status_t I2C_ReadRegister(uint8_t deviceAddress, uint32_t regAddress, uint8_t *regData, size_t dataSize);

#if defined(__cplusplus)
}
#endif

#endif /* AUTH_ARD_I2C_COMMON_H_ */
