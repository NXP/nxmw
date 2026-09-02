/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef APP_AUTH_ARD_H_
#define APP_AUTH_ARD_H_

#include "fsl_clock.h"
#include "fsl_lpi2c.h"
#include "fsl_gpio.h"
#include "pin_mux.h"

#include "auth_ard_io_exp.h"
#include "auth_ard_i2c_common.h"
#include "auth_ard_ssd1306_i2c_oled.h"
#include "auth_ard_temp_sensor.h"

/** @brief LPI2C baud rate in Hz */
#define LPI2C_BAUDRATE               400000U

/** @brief LPI2C master clock frequency retrieved from the clock manager */
#define LPI2C_MASTER_CLOCK_FREQUENCY CLOCK_GetLpi2cClkFreq()

/** @brief IRQ handler for the Auth ARD I/O expander interrupt */
#define AUTH_ARD_IO_EXP_IRQ_HANDLER  GPIO2_IRQHandler

/** @brief IRQ number for the Auth ARD I/O expander interrupt */
#define AUTH_ARD_IO_EXP_IRQ   GPIO2_IRQn

/* --- GPIO symbols for the Auth ARD I/O expander interrupt pin --- */

/** @brief GPIO peripheral base pointer for the I/O expander interrupt */
#define BOARD_INITPINS_AUTH_ARD_IO_EXP_INT_GPIO          GPIO2

/** @brief GPIO pin number for the I/O expander interrupt */
#define BOARD_INITPINS_AUTH_ARD_IO_EXP_INT_GPIO_PIN      4U

/** @brief GPIO pin mask for the I/O expander interrupt */
#define BOARD_INITPINS_AUTH_ARD_IO_EXP_INT_GPIO_PIN_MASK (1U << 4U)

/* --- PORT symbols for the Auth ARD I/O expander interrupt pin --- */

/** @brief PORT peripheral base pointer for the I/O expander interrupt */
#define BOARD_INITPINS_AUTH_ARD_IO_EXP_INT_PORT          PORT2

/** @brief PORT pin number for the I/O expander interrupt */
#define BOARD_INITPINS_AUTH_ARD_IO_EXP_INT_PIN           4U

/** @brief PORT pin mask for the I/O expander interrupt */
#define BOARD_INITPINS_AUTH_ARD_IO_EXP_INT_PIN_MASK      (1U << 4U)

/**
		* @brief Initializes the LPI2C master interface for the Auth ARD board.
		*
		* This function configures and initializes the LPI2C master peripheral
		* with the specified baud rate, using the default master configuration
		* as a base.
		*
		* @param i2c_baudRate_Hz Desired I2C communication baud rate in Hz.
		*/
void app_auth_ard_i2c_Interface_Init(uint32_t i2c_baudRate_Hz);

/**
		* @brief Initializes the PCAL6408A I2C I/O expander on the Auth ARD board.
		*
		* This function configures the I/O expander with the desired pin directions,
		* input polarity, output logic levels, power switches, LEDs, interrupt
		* service routines (ISR), and input latch settings, then applies the
		* configuration by calling auth_ard_IO_ExpanderInit().
		*/
void app_auth_ard_io_expander_Init(void);

#endif /* APP_AUTH_ARD_H_ */
