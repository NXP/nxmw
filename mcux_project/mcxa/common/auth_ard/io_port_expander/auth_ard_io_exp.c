/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "auth_ard_io_exp.h"

/* ************************************************************************** */
/* Definitions                                                                */
/* ************************************************************************** */

#define PCAL6408A_INPUT_PORT_REG   (0x00U) /*!< Input port Read byte */
#define PCAL6408A_OUTPUT_PORT_REG  (0x01U) /*!< Output port Read/write byte */
#define PCAL6408A_INPUT_INVERT_REG (0x02U) /*!< Polarity Inversion Read/write byte */
#define PCAL6408A_IO_CONFIG_REG    (0x03U) /*!< Configuration Read/write byte */
#define PCAL6408A_INPUT_LATCH_REG  (0x42U) /*!< Input latch Read/write byte */
#define PCAL6408A_ISR_MASK_REG     (0x45U) /*!< Interrupt mask Read/write byte */
#define PCAL6408A_ISR_STATUS_REG   (0x46U) /*!< Interrupt status Read byte */

/* ************************************************************************** */
/* Private Variables                                                          */
/* ************************************************************************** */

static uint8_t s_outputRegValue = 0U; /*!< Output Register Value */

/* ************************************************************************** */
/* Private Function Prototypes                                                */
/* ************************************************************************** */

/*!
 * @brief Generic helper to set or clear a bit in the output register and write it.
 *
 * @param mask     Bitmask of the pin to control.
 * @param value    Desired output state (kAuth_ARD_On or kAuth_ARD_Off).
 * @param inverted If true, logic is inverted (used for P-MOSFET power switches).
 *
 * @return status_t Status code indicating success or failure.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
static status_t auth_ard_PCAL6408A_SetOutputPin(uint8_t mask, auth_ard_io_exp_output_state_t value, bool inverted);

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/*!
 * brief Initializes the Auth ARD PCAL6408A I2C I/O expander configuration structure with default values.
 *
 * This function sets default configuration values for all I/O pins:
 * - P0-P3 (AIO1, AIO2, BIO1, BIO2): Configured as inputs with inverted polarity
 * - P4-P7 (Power switches and LEDs): Configured as outputs in OFF state
 * - All interrupts and input latches: Disabled
 *
 * param io_expander_config Pointer to the configuration structure to initialize.
 */
void auth_ard_IO_ExpanderGetDefaultConfig(auth_ard_io_exp_config_t *io_expander_config)
{
	if (io_expander_config == NULL)
	{
		return;
	}

	/* Configure P0-P3 as inputs */
	io_expander_config->io_exp_AIO1_Direction = kAuth_ARD_Input;
	io_expander_config->io_exp_AIO2_Direction = kAuth_ARD_Input;
	io_expander_config->io_exp_BIO1_Direction = kAuth_ARD_Input;
	io_expander_config->io_exp_BIO2_Direction = kAuth_ARD_Input;

	/* Configure input polarity inversion for P0-P3 */
	io_expander_config->io_exp_AIO1_InvertInput = kAuth_ARD_InputInvert;
	io_expander_config->io_exp_AIO2_InvertInput = kAuth_ARD_InputInvert;
	io_expander_config->io_exp_BIO1_InvertInput = kAuth_ARD_InputInvert;
	io_expander_config->io_exp_BIO2_InvertInput = kAuth_ARD_InputInvert;

	/* Configure default output logic levels for P0-P3 */
	io_expander_config->io_exp_AIO1_OutputLogic = kAuth_ARD_Low;
	io_expander_config->io_exp_AIO2_OutputLogic = kAuth_ARD_Low;
	io_expander_config->io_exp_BIO1_OutputLogic = kAuth_ARD_Low;
	io_expander_config->io_exp_BIO2_OutputLogic = kAuth_ARD_Low;

	/* Configure P4-P7 outputs to OFF state */
	io_expander_config->io_exp_EVK_B_Power = kAuth_ARD_Off;
	io_expander_config->io_exp_EVK_A_Power = kAuth_ARD_Off;
	io_expander_config->io_exp_LED1        = kAuth_ARD_Off;
	io_expander_config->io_exp_LED2        = kAuth_ARD_Off;

	/* Disable interrupts for P0-P3 */
	io_expander_config->io_exp_AIO1_ISR_Enabled = kAuth_ARD_Disable;
	io_expander_config->io_exp_AIO2_ISR_Enabled = kAuth_ARD_Disable;
	io_expander_config->io_exp_BIO1_ISR_Enabled = kAuth_ARD_Disable;
	io_expander_config->io_exp_BIO2_ISR_Enabled = kAuth_ARD_Disable;

	/* Disable input latches for P0-P3 */
	io_expander_config->io_exp_AIO1_InputLatch_Enabled = kAuth_ARD_Disable;
	io_expander_config->io_exp_AIO2_InputLatch_Enabled = kAuth_ARD_Disable;
	io_expander_config->io_exp_BIO1_InputLatch_Enabled = kAuth_ARD_Disable;
	io_expander_config->io_exp_BIO2_InputLatch_Enabled = kAuth_ARD_Disable;
}

/*!
 * brief Initializes the Auth ARD PCAL6408A I2C I/O port expander.
 *
 * This function sets up the input/output directions, output values,
 * input latch register and interrupt mask for the PCAL6408A I/O expander
 * based on the provided configuration.
 *
 * Auth ARD I2C Port Expander GPIO mapping:
 * - P7: LED2 (always output)
 * - P6: LED1 (always output)
 * - P5: EVK A Power Off (always output)
 * - P4: EVK B/C/D Power Off (always output)
 * - P3: EVK A IO1 or button AIO1 / LED (input/output)
 * - P2: EVK A IO2 or button AIO2 / LED (input/output)
 * - P1: EVK B/C/D IO1 or button BIO1 / LED (input/output)
 * - P0: EVK B/C/D IO2 or button BIO2 / LED (input/output)
 *
 * note Pins P4-P7 are always configured as outputs. Pins P0-P3 are configured based on
 *       the direction settings in the configuration structure.
 *
 * note The following PCAL6408A ports, when configured as inputs, can trigger an interrupt:
 *       - P3: EVK A IO1 or button AIO1
 *       - P2: EVK A IO2 or button AIO2
 *       - P1: EVK B/C/D IO1 or button BIO1
 *       - P0: EVK B/C/D IO2 or button BIO2
 *
 * param io_expander_config Configuration structure containing I/O directions,
 *        initial output states, input polarity inversion and input interrupt
 *        settings for the corresponding I/O pin of the expander.
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was received successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_IO_ExpanderInit(auth_ard_io_exp_config_t io_expander_config)
{
	status_t result                      = kStatus_Fail;
	uint8_t port0_3_direction            = 0U;
	uint8_t port0_3_polarity_inversion   = 0U;
	uint8_t isrMask                      = 0U;
	uint8_t inputLatchMask               = 0U;

	/* Prepare output register value */
	s_outputRegValue = ((uint8_t)(io_expander_config.io_exp_LED2 << AUTH_ARD_LED2_SHIFT) |
	                    (uint8_t)(io_expander_config.io_exp_LED1 << AUTH_ARD_LED1_SHIFT) |
	                    (uint8_t)(io_expander_config.io_exp_EVK_A_Power << AUTH_ARD_EVK_A_PWR_SW_SHIFT) |
	                    (uint8_t)(io_expander_config.io_exp_EVK_B_Power << AUTH_ARD_EVK_B_PWR_SW_SHIFT) |
	                    (uint8_t)(io_expander_config.io_exp_BIO2_OutputLogic << AUTH_ARD_BIO2_SHIFT) |
	                    (uint8_t)(io_expander_config.io_exp_BIO1_OutputLogic << AUTH_ARD_BIO1_SHIFT) |
	                    (uint8_t)(io_expander_config.io_exp_AIO2_OutputLogic << AUTH_ARD_AIO2_SHIFT) |
	                    (uint8_t)(io_expander_config.io_exp_AIO1_OutputLogic << AUTH_ARD_AIO1_SHIFT));

	/* EVK MOSFET Power switches are controlled by negative logic */
	s_outputRegValue ^= ((uint8_t)(1U << AUTH_ARD_EVK_A_PWR_SW_SHIFT) |
	                     (uint8_t)(1U << AUTH_ARD_EVK_B_PWR_SW_SHIFT));

	/* Configure the PCAL6408A output register */
	result = I2C_WriteRegisterByte(PCAL6408A_I2C_ADDR, PCAL6408A_OUTPUT_PORT_REG, s_outputRegValue);
	AUTH_ARD_ENSURE_OR_GO_CLEANUP(kStatus_Success == result)

	/* Prepare polarity inversion register value for P0-P3 */
	port0_3_polarity_inversion = ((uint8_t)(io_expander_config.io_exp_AIO1_InvertInput << AUTH_ARD_AIO1_SHIFT) |
	                              (uint8_t)(io_expander_config.io_exp_AIO2_InvertInput << AUTH_ARD_AIO2_SHIFT) |
	                              (uint8_t)(io_expander_config.io_exp_BIO1_InvertInput << AUTH_ARD_BIO1_SHIFT) |
	                              (uint8_t)(io_expander_config.io_exp_BIO2_InvertInput << AUTH_ARD_BIO2_SHIFT));

	/* Configure the PCAL6408A polarity inversion register for P0–P3 */
	result = I2C_WriteRegisterByte(PCAL6408A_I2C_ADDR, PCAL6408A_INPUT_INVERT_REG, 0x0FU & port0_3_polarity_inversion);
	AUTH_ARD_ENSURE_OR_GO_CLEANUP(kStatus_Success == result)

	/* Prepare input latch mask */
	inputLatchMask = ((uint8_t)(io_expander_config.io_exp_BIO2_InputLatch_Enabled << AUTH_ARD_BIO2_SHIFT) |
	                  (uint8_t)(io_expander_config.io_exp_BIO1_InputLatch_Enabled << AUTH_ARD_BIO1_SHIFT) |
	                  (uint8_t)(io_expander_config.io_exp_AIO2_InputLatch_Enabled << AUTH_ARD_AIO2_SHIFT) |
	                  (uint8_t)(io_expander_config.io_exp_AIO1_InputLatch_Enabled << AUTH_ARD_AIO1_SHIFT));

	/* Configure input latch register (positive logic) */
	result = I2C_WriteRegisterByte(PCAL6408A_I2C_ADDR, PCAL6408A_INPUT_LATCH_REG, inputLatchMask);
	AUTH_ARD_ENSURE_OR_GO_CLEANUP(kStatus_Success == result)

	/* Prepare ISR mask */
	isrMask = ((uint8_t)(io_expander_config.io_exp_BIO2_ISR_Enabled << AUTH_ARD_BIO2_SHIFT) |
	           (uint8_t)(io_expander_config.io_exp_BIO1_ISR_Enabled << AUTH_ARD_BIO1_SHIFT) |
	           (uint8_t)(io_expander_config.io_exp_AIO2_ISR_Enabled << AUTH_ARD_AIO2_SHIFT) |
	           (uint8_t)(io_expander_config.io_exp_AIO1_ISR_Enabled << AUTH_ARD_AIO1_SHIFT));

	/* PCAL6408A ISR enable uses negative logic */
	isrMask = ~isrMask;

	/* Configure interrupt mask register */
	result = I2C_WriteRegisterByte(PCAL6408A_I2C_ADDR, PCAL6408A_ISR_MASK_REG, isrMask);
	AUTH_ARD_ENSURE_OR_GO_CLEANUP(kStatus_Success == result)

	/* Prepare port direction configuration for P0-P3 */
	port0_3_direction = ((uint8_t)(io_expander_config.io_exp_AIO1_Direction << AUTH_ARD_AIO1_SHIFT) |
	                     (uint8_t)(io_expander_config.io_exp_AIO2_Direction << AUTH_ARD_AIO2_SHIFT) |
	                     (uint8_t)(io_expander_config.io_exp_BIO1_Direction << AUTH_ARD_BIO1_SHIFT) |
	                     (uint8_t)(io_expander_config.io_exp_BIO2_Direction << AUTH_ARD_BIO2_SHIFT));

	/* Configure PCAL6408A P0-P3 as input/output based on io_expander_config;
	 * PCAL6408A P4-P7 are fixed as outputs */
	result = I2C_WriteRegisterByte(PCAL6408A_I2C_ADDR, PCAL6408A_IO_CONFIG_REG, 0x0FU & port0_3_direction);
	AUTH_ARD_ENSURE_OR_GO_CLEANUP(kStatus_Success == result)

cleanup:
	return result;
}

/*!
 * brief Controls the state of EVK A Power Switch (P-MOSFET Q2) connected via PCAL6408A I2C I/O expander (port pin P5).
 *
 * param switch_value Desired Power state:
 *                    - kAuth_ARD_Off: Turn off EVK A Power Supply
 *                    - kAuth_ARD_On: Turn on EVK A Power Supply
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_EVK_A_Power(auth_ard_io_exp_output_state_t switch_value)
{
	return auth_ard_PCAL6408A_SetOutputPin(AUTH_ARD_EVK_A_PWR_SW_MASK, switch_value, true);
}

/*!
 * brief Controls the state of EVK B/C/D Power Switch (P-MOSFET Q1) connected via PCAL6408A I2C I/O expander (port pin P4).
 *
 * param switch_value Desired Power state:
 *                    - kAuth_ARD_Off: Turn off EVK B/C/D Power Supply
 *                    - kAuth_ARD_On: Turn on EVK B/C/D Power Supply
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_EVK_B_Power(auth_ard_io_exp_output_state_t switch_value)
{
	return auth_ard_PCAL6408A_SetOutputPin(AUTH_ARD_EVK_B_PWR_SW_MASK, switch_value, true);
}

/*!
 * brief Controls the state of LED1 connected via the PCAL6408A I2C I/O expander (port pin P6).
 *
 * param led_value Desired LED state:
 *                 - kAuth_ARD_Off: Turn off LED1
 *                 - kAuth_ARD_On: Turn on LED1
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_LED1(auth_ard_io_exp_output_state_t led_value)
{
	return auth_ard_PCAL6408A_SetOutputPin(AUTH_ARD_LED1_MASK, led_value, false);
}

/*!
 * brief Controls the state of LED2 connected via the PCAL6408A I2C I/O expander (port pin P7).
 *
 * param led_value Desired LED state:
 *                 - kAuth_ARD_Off: Turn off LED2
 *                 - kAuth_ARD_On: Turn on LED2
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_LED2(auth_ard_io_exp_output_state_t led_value)
{
	return auth_ard_PCAL6408A_SetOutputPin(AUTH_ARD_LED2_MASK, led_value, false);
}

/*!
 * brief Sets the state of AIO1 (PCAL6408A I2C I/O expander port pin P3).
 *
 * note Ensure that the AIO1 port direction is configured as output before calling this function.
 *
 * param output_value Desired output state:
 *                    - kAuth_ARD_Low: Sets AIO1 low (turn on LED '0', turn off LED '1')
 *                    - kAuth_ARD_High: Sets AIO1 high (turn off LED '0', turn on LED '1')
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_AIO1_Out(auth_ard_io_exp_output_state_t output_value)
{
	return auth_ard_PCAL6408A_SetOutputPin(AUTH_ARD_AIO1_MASK, output_value, false);
}

/*!
 * brief Sets the state of AIO2 (PCAL6408A I2C I/O expander port pin P2).
 *
 * note Ensure that the AIO2 port direction is configured as output before calling this function.
 *
 * param output_value Desired output state:
 *                    - kAuth_ARD_Low: Sets AIO2 low (turn on LED '0', turn off LED '1')
 *                    - kAuth_ARD_High: Sets AIO2 high (turn off LED '0', turn on LED '1')
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_AIO2_Out(auth_ard_io_exp_output_state_t output_value)
{
	return auth_ard_PCAL6408A_SetOutputPin(AUTH_ARD_AIO2_MASK, output_value, false);
}

/*!
 * brief Sets the state of BIO1 (PCAL6408A I2C I/O expander port pin P1).
 *
 * note Ensure that the BIO1 port direction is configured as output before calling this function.
 *
 * param output_value Desired output state:
 *                    - kAuth_ARD_Low: Sets BIO1 low (turn on LED '0', turn off LED '1')
 *                    - kAuth_ARD_High: Sets BIO1 high (turn off LED '0', turn on LED '1')
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_BIO1_Out(auth_ard_io_exp_output_state_t output_value)
{
	return auth_ard_PCAL6408A_SetOutputPin(AUTH_ARD_BIO1_MASK, output_value, false);
}

/*!
 * brief Sets the state of BIO2 (PCAL6408A I2C I/O expander port pin P0).
 *
 * note Ensure that the BIO2 port direction is configured as output before calling this function.
 *
 * param output_value Desired output state:
 *                    - kAuth_ARD_Low: Sets BIO2 low (turn on LED '0', turn off LED '1')
 *                    - kAuth_ARD_High: Sets BIO2 high (turn off LED '0', turn on LED '1')
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was written successfully.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_BIO2_Out(auth_ard_io_exp_output_state_t output_value)
{
	return auth_ard_PCAL6408A_SetOutputPin(AUTH_ARD_BIO2_MASK, output_value, false);
}

/*!
 * brief Reads the current value from the Auth ARD PCAL6408A I2C I/O port expander Input Port Register (P0 to P7).
 *
 * note An active PCAL6408A I2C I/O port expander interrupt is cleared when the Input Port Register is read.
 *
 * param input_value Pointer to a variable where the input port value will be stored.
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was read successfully.
 *         - #kStatus_InvalidArgument input_value pointer is NULL.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_ReadInputPort(uint8_t *input_value)
{
	if (input_value == NULL)
	{
		return kStatus_InvalidArgument;
	}
	return I2C_ReadRegisterByte(PCAL6408A_I2C_ADDR, PCAL6408A_INPUT_PORT_REG, input_value);
}

/*!
 * brief Reads the current value from the Auth ARD PCAL6408A I2C I/O port expander Interrupt Status Register (P0 to P7).
 *
 * param isr_status Pointer to a variable where the interrupt status value will be stored.
 *
 * return status_t Status code indicating success or failure of the operation.
 *         - #kStatus_Success Data was read successfully.
 *         - #kStatus_InvalidArgument isr_status pointer is NULL.
 *         - #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 *         - #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 *         - #kStatus_LPI2C_FifoError FIFO under run or overrun.
 *         - #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 *         - #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_ReadIsrStatus(uint8_t *isr_status)
{
	if (isr_status == NULL)
	{
		return kStatus_InvalidArgument;
	}
	return I2C_ReadRegisterByte(PCAL6408A_I2C_ADDR, PCAL6408A_ISR_STATUS_REG, isr_status);
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

static status_t auth_ard_PCAL6408A_SetOutputPin(uint8_t mask, auth_ard_io_exp_output_state_t value, bool inverted)
{
	bool set_bit = (value != kAuth_ARD_Off);

	if (inverted)
	{
		set_bit = !set_bit;
	}

	if (set_bit)
	{
		s_outputRegValue |= mask;
	}
	else
	{
		s_outputRegValue &= ~mask;
	}

	return I2C_WriteRegisterByte(PCAL6408A_I2C_ADDR, PCAL6408A_OUTPUT_PORT_REG, s_outputRegValue);
}
