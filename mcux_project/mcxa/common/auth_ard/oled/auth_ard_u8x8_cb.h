/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef AUTH_ARD_U8X8_CB_H_
#define AUTH_ARD_U8X8_CB_H_

#ifdef __cplusplus
extern "C" {
#endif

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "auth_ard_i2c_common.h"
#include "fsl_clock.h"
#include "fsl_common_arm.h"
#include "u8g2.h"

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/*! @brief SSD1306 OLED display I2C address */
#define SSD_1306_I2C_ADDR (0x3CU)

/*! @brief Maximum I2C buffer size for u8x8 library communication */
#define AUTH_ARD_U8X8_I2C_BUFFER_SIZE (32U)

/* ************************************************************************** */
/* API Functions                                                              */
/* ************************************************************************** */

/*!
 * @brief GPIO and delay callback for u8x8/u8g2 library
 *
 * This function handles GPIO and delay-related messages from the u8x8 library.
 * It is used to interface with the display hardware.
 *
 * @param u8x8 Pointer to the u8x8 structure
 * @param msg Message type from the u8x8 library
 * @param arg_int Integer argument (e.g., delay time in milliseconds or microseconds)
 * @param arg_ptr Pointer argument (not used in this implementation)
 *
 * @return Always returns 1 (success)
 */
uint8_t auth_ard_u8x8_gpio_and_delay(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr);

/*!
 * @brief I2C communication callback for u8x8/u8g2 library
 *
 * This function handles I2C communication messages from the u8x8 library.
 * It buffers data and sends it via I2C to the display.
 *
 * @param u8x8 Pointer to the u8x8 structure
 * @param msg Message type from the u8x8 library
 * @param arg_int Integer argument (e.g., number of bytes to send)
 * @param arg_ptr Pointer to data buffer
 *
 * @return 1 on success, 0 on unsupported message or buffer overflow
 */
uint8_t auth_ard_u8x8_i2c(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr);

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif /* AUTH_ARD_U8X8_CB_H_ */
