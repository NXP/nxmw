/*
		*
		* Copyright 2025 NXP
		* SPDX-License-Identifier: BSD-3-Clause
		*/

#include "app_auth_ard.h"

/**
		* @brief Initializes the LPI2C master interface for the Auth ARD board.
		*
		* This function configures and initializes the LPI2C master peripheral
		* with the specified baud rate, using the default master configuration
		* as a base.
		*
		* @param i2c_baudRate_Hz Desired I2C communication baud rate in Hz.
		*/
void app_auth_ard_i2c_Interface_Init(uint32_t i2c_baudRate_Hz)
{
					lpi2c_master_config_t masterConfig;

					/* Load the default LPI2C master configuration */
					LPI2C_MasterGetDefaultConfig(&masterConfig);

					/* Override the default I2C baud rate configuration */
					masterConfig.baudRate_Hz = i2c_baudRate_Hz;

					/* Initialize the LPI2C master peripheral with the updated configuration */
					LPI2C_MasterInit(AUTH_ARD_I2CM, &masterConfig, LPI2C_MASTER_CLOCK_FREQUENCY);
}

/**
		* @brief Initializes the PCAL6408A I2C I/O expander on the Auth ARD board.
		*
		* This function configures the I/O expander with the desired pin directions,
		* input polarity, output logic levels, power switches, LEDs, interrupt
		* service routines (ISR), and input latch settings, then applies the
		* configuration by calling auth_ard_IO_ExpanderInit().
		*/
void app_auth_ard_io_expander_Init(void)
{
		/* -------------------------------------------------- */
		/* Configure the Auth ARD PCAL6408A I2C I/O expander  */
		/* -------------------------------------------------- */
		auth_ard_io_exp_config_t io_exp_config = {
			/* Configure port direction: kAuth_ARD_Input or kAuth_ARD_Output */
			.io_exp_AIO1_Direction = kAuth_ARD_Input,
			.io_exp_AIO2_Direction = kAuth_ARD_Input,
			.io_exp_BIO1_Direction = kAuth_ARD_Input,
			.io_exp_BIO2_Direction = kAuth_ARD_Input,

			/* Configure input polarity inversion:
				* kAuth_ARD_InputNormal or kAuth_ARD_InputInvert
				* Note: Has no effect in output mode */
			.io_exp_AIO1_InvertInput = kAuth_ARD_InputNormal,
			.io_exp_AIO2_InvertInput = kAuth_ARD_InputNormal,
			.io_exp_BIO1_InvertInput = kAuth_ARD_InputNormal,
			.io_exp_BIO2_InvertInput = kAuth_ARD_InputNormal,

			/* Set output logic level: kAuth_ARD_Low or kAuth_ARD_High
				* Note: Has no effect in input mode */
			.io_exp_AIO1_OutputLogic = kAuth_ARD_Low,
			.io_exp_AIO2_OutputLogic = kAuth_ARD_Low,
			.io_exp_BIO1_OutputLogic = kAuth_ARD_Low,
			.io_exp_BIO2_OutputLogic = kAuth_ARD_Low,

			/* Set the EVK power switches: kAuth_ARD_On or kAuth_ARD_Off */
			.io_exp_EVK_A_Power = kAuth_ARD_On,
			.io_exp_EVK_B_Power = kAuth_ARD_On,

			/* Set the Auth ARD board LEDs: kAuth_ARD_On or kAuth_ARD_Off */
			.io_exp_LED1 = kAuth_ARD_Off,
			.io_exp_LED2 = kAuth_ARD_Off,

			/* Enable or disable the ISR: kAuth_ARD_Enable or kAuth_ARD_Disable
				* Note: Has no effect in output mode */
			.io_exp_AIO1_ISR_Enabled = kAuth_ARD_Disable,
			.io_exp_AIO2_ISR_Enabled = kAuth_ARD_Disable,
			.io_exp_BIO1_ISR_Enabled = kAuth_ARD_Disable,
			.io_exp_BIO2_ISR_Enabled = kAuth_ARD_Disable,

			/* Enable or disable the input latch: kAuth_ARD_Enable or kAuth_ARD_Disable
				* Note: Has no effect in output mode */
			.io_exp_AIO1_InputLatch_Enabled = kAuth_ARD_Disable,
			.io_exp_AIO2_InputLatch_Enabled = kAuth_ARD_Disable,
			.io_exp_BIO1_InputLatch_Enabled = kAuth_ARD_Disable,
			.io_exp_BIO2_InputLatch_Enabled = kAuth_ARD_Disable,
		};

		/* Apply the I/O expander configuration */
		auth_ard_IO_ExpanderInit(io_exp_config);
}
