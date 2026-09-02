/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef AUTH_ARD_I2C_PORT_EXPANDER_H
#define AUTH_ARD_I2C_PORT_EXPANDER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include "auth_ard_i2c_common.h"

/*!
 * @addtogroup auth_ard_io_expander
 * @{
 */

/* ************************************************************************** */
/* Definitions                                                                */
/* ************************************************************************** */

/*!
 * @name Auth ARD I2C Port Expander GPIO Mapping
 * @{
 */
/*! @brief Auth ARD I2C Port Expander GPIO mapping
 *
 * Pin Assignment:
 * - P7: LED2 (always output)
 * - P6: LED1 (always output)
 * - P5: EVK A Power Off (always output)
 * - P4: EVK B/C/D Power Off (always output)
 * - P3: EVK A IO1 or button AIO1 / LED (input/output)
 * - P2: EVK A IO2 or button AIO2 / LED (input/output)
 * - P1: EVK B/C/D IO1 or button BIO1 / LED (input/output)
 * - P0: EVK B/C/D IO2 or button BIO2 / LED (input/output)
 */
/*! @} */

/*! @brief PCAL6408A I2C device address */
#define PCAL6408A_I2C_ADDR (0x21U)

/*! @brief Output state ON value */
#define AUTH_ARD_ON  (1U)
/*! @brief Output state OFF value */
#define AUTH_ARD_OFF (0U)

/*! @brief Enable value */
#define AUTH_ARD_ENABLE  (1U)
/*! @brief Disable value */
#define AUTH_ARD_DISABLE (0U)

/*! @name Port Pin Bit Shift Definitions
 * @{
 */
#define AUTH_ARD_LED2_SHIFT         (7U) /*!< LED2 bit position */
#define AUTH_ARD_LED1_SHIFT         (6U) /*!< LED1 bit position */
#define AUTH_ARD_EVK_A_PWR_SW_SHIFT (5U) /*!< EVK A power switch bit position */
#define AUTH_ARD_EVK_B_PWR_SW_SHIFT (4U) /*!< EVK B/C/D power switch bit position */
#define AUTH_ARD_AIO1_SHIFT         (3U) /*!< AIO1 bit position */
#define AUTH_ARD_AIO2_SHIFT         (2U) /*!< AIO2 bit position */
#define AUTH_ARD_BIO1_SHIFT         (1U) /*!< BIO1 bit position */
#define AUTH_ARD_BIO2_SHIFT         (0U) /*!< BIO2 bit position */
/*! @} */

/*! @name Port Pin Bit Mask Definitions
 * @{
 */
#define AUTH_ARD_LED2_MASK         (0x80U) /*!< LED2 bit mask */
#define AUTH_ARD_LED1_MASK         (0x40U) /*!< LED1 bit mask */
#define AUTH_ARD_EVK_A_PWR_SW_MASK (0x20U) /*!< EVK A power switch bit mask */
#define AUTH_ARD_EVK_B_PWR_SW_MASK (0x10U) /*!< EVK B/C/D power switch bit mask */
#define AUTH_ARD_AIO1_MASK         (0x08U) /*!< AIO1 bit mask */
#define AUTH_ARD_AIO2_MASK         (0x04U) /*!< AIO2 bit mask */
#define AUTH_ARD_BIO1_MASK         (0x02U) /*!< BIO1 bit mask */
#define AUTH_ARD_BIO2_MASK         (0x01U) /*!< BIO2 bit mask */
/*! @} */

/*! @name Convenience Macros for EVK Power Control
 * @{
 */
/*! @brief Turn on EVK A power supply */
#define AUTH_ARD_EVK_A_POWER_ON()  auth_ard_EVK_A_Power(kAuth_ARD_On)
/*! @brief Turn off EVK A power supply */
#define AUTH_ARD_EVK_A_POWER_OFF() auth_ard_EVK_A_Power(kAuth_ARD_Off)

/*! @brief Turn on EVK B/C/D power supply */
#define AUTH_ARD_EVK_B_POWER_ON()  auth_ard_EVK_B_Power(kAuth_ARD_On)
/*! @brief Turn off EVK B/C/D power supply */
#define AUTH_ARD_EVK_B_POWER_OFF() auth_ard_EVK_B_Power(kAuth_ARD_Off)
/*! @} */

/*! @name Convenience Macros for LED Control
 * @{
 */
/*! @brief Turn on LED1 */
#define AUTH_ARD_LED1_ON()  auth_ard_LED1(kAuth_ARD_On)
/*! @brief Turn off LED1 */
#define AUTH_ARD_LED1_OFF() auth_ard_LED1(kAuth_ARD_Off)

/*! @brief Turn on LED2 */
#define AUTH_ARD_LED2_ON()  auth_ard_LED2(kAuth_ARD_On)
/*! @brief Turn off LED2 */
#define AUTH_ARD_LED2_OFF() auth_ard_LED2(kAuth_ARD_Off)
/*! @} */

/*! @name Convenience Macros for AIO Output Control
 * @{
 */
/*! @brief Set AIO1 output high */
#define AUTH_ARD_AIO1_OUT_ON()  auth_ard_AIO1_Out(kAuth_ARD_On)
/*! @brief Set AIO1 output low */
#define AUTH_ARD_AIO1_OUT_OFF() auth_ard_AIO1_Out(kAuth_ARD_Off)

/*! @brief Set AIO2 output high */
#define AUTH_ARD_AIO2_OUT_ON()  auth_ard_AIO2_Out(kAuth_ARD_On)
/*! @brief Set AIO2 output low */
#define AUTH_ARD_AIO2_OUT_OFF() auth_ard_AIO2_Out(kAuth_ARD_Off)
/*! @} */

/*! @name Convenience Macros for BIO Output Control
 * @{
 */
/*! @brief Set BIO1 output high */
#define AUTH_ARD_BIO1_OUT_ON()  auth_ard_BIO1_Out(kAuth_ARD_On)
/*! @brief Set BIO1 output low */
#define AUTH_ARD_BIO1_OUT_OFF() auth_ard_BIO1_Out(kAuth_ARD_Off)

/*! @brief Set BIO2 output high */
#define AUTH_ARD_BIO2_OUT_ON()  auth_ard_BIO2_Out(kAuth_ARD_On)
/*! @brief Set BIO2 output low */
#define AUTH_ARD_BIO2_OUT_OFF() auth_ard_BIO2_Out(kAuth_ARD_Off)
/*! @} */

/* ************************************************************************** */
/* Type Definitions                                                           */
/* ************************************************************************** */

/*! @brief Auth ARD IO port expander - I/O direction definition */
typedef enum _auth_ard_io_exp_dir_t
{
    kAuth_ARD_Output = 0U, /*!< Set current port as digital output */
    kAuth_ARD_Input  = 1U, /*!< Set current port as digital input */
} auth_ard_io_exp_dir_t;

/*! @brief Auth ARD IO port expander - Input polarity inversion */
typedef enum _auth_ard_io_exp_invet_input_t
{
    kAuth_ARD_InputNormal = 0U, /*!< Digital input is not inverted */
    kAuth_ARD_InputInvert = 1U, /*!< Digital input is inverted */
} auth_ard_io_exp_invet_input_t;

/*! @brief Auth ARD IO port expander - Logic level definition */
typedef enum _auth_ard_io_exp_logic_level_t
{
    kAuth_ARD_Low  = 0U, /*!< Set current port to logic level low */
    kAuth_ARD_High = 1U, /*!< Set current port to logic level high */
} auth_ard_io_exp_logic_level_t;

/*! @brief Auth ARD IO port expander - Output state definition */
typedef enum _auth_ard_io_exp_output_state_t
{
    kAuth_ARD_Off = 0U, /*!< Output state off */
    kAuth_ARD_On  = 1U, /*!< Output state on */
} auth_ard_io_exp_output_state_t;

/*! @brief Auth ARD IO port expander - ISR enable definition */
typedef enum _auth_ard_io_exp_isr_t
{
    kAuth_ARD_Disable = 0U, /*!< Disable input port ISR source */
    kAuth_ARD_Enable  = 1U, /*!< Enable input port ISR source */
} auth_ard_io_exp_isr_t;

/*!
 * @brief Configuration structure for the Auth ARD PCAL6408A I2C I/O expander.
 *
 * This structure contains all configuration parameters for the PCAL6408A I/O expander,
 * including port directions, output states, input polarity inversion, interrupt settings,
 * and input latch configuration.
 */
typedef struct _auth_ard_io_exp_config_t
{
    /* Port Direction Configuration (P0-P3) */
    auth_ard_io_exp_dir_t io_exp_AIO1_Direction; /*!< AIO1 port direction, input or output mode */
    auth_ard_io_exp_dir_t io_exp_AIO2_Direction; /*!< AIO2 port direction, input or output mode */
    auth_ard_io_exp_dir_t io_exp_BIO1_Direction; /*!< BIO1 port direction, input or output mode */
    auth_ard_io_exp_dir_t io_exp_BIO2_Direction; /*!< BIO2 port direction, input or output mode */

    /* Input Polarity Inversion Configuration (P0-P3) */
    auth_ard_io_exp_invet_input_t io_exp_AIO1_InvertInput; /*!< AIO1 input polarity inversion (no effect in output mode) */
    auth_ard_io_exp_invet_input_t io_exp_AIO2_InvertInput; /*!< AIO2 input polarity inversion (no effect in output mode) */
    auth_ard_io_exp_invet_input_t io_exp_BIO1_InvertInput; /*!< BIO1 input polarity inversion (no effect in output mode) */
    auth_ard_io_exp_invet_input_t io_exp_BIO2_InvertInput; /*!< BIO2 input polarity inversion (no effect in output mode) */

    /* Output Logic Level Configuration (P0-P3) */
    auth_ard_io_exp_logic_level_t io_exp_AIO1_OutputLogic; /*!< AIO1 output logic level (no effect in input mode) */
    auth_ard_io_exp_logic_level_t io_exp_AIO2_OutputLogic; /*!< AIO2 output logic level (no effect in input mode) */
    auth_ard_io_exp_logic_level_t io_exp_BIO1_OutputLogic; /*!< BIO1 output logic level (no effect in input mode) */
    auth_ard_io_exp_logic_level_t io_exp_BIO2_OutputLogic; /*!< BIO2 output logic level (no effect in input mode) */

    /* Power Switch and LED Configuration (P4-P7, always outputs) */
    auth_ard_io_exp_output_state_t io_exp_EVK_B_Power; /*!< EVK B/C/D power switch state */
    auth_ard_io_exp_output_state_t io_exp_EVK_A_Power; /*!< EVK A power switch state */
    auth_ard_io_exp_output_state_t io_exp_LED1;        /*!< LED1 output state */
    auth_ard_io_exp_output_state_t io_exp_LED2;        /*!< LED2 output state */

    /* Interrupt Configuration (P0-P3) */
    auth_ard_io_exp_isr_t io_exp_AIO1_ISR_Enabled; /*!< AIO1 interrupt enable (no effect in output mode) */
    auth_ard_io_exp_isr_t io_exp_AIO2_ISR_Enabled; /*!< AIO2 interrupt enable (no effect in output mode) */
    auth_ard_io_exp_isr_t io_exp_BIO1_ISR_Enabled; /*!< BIO1 interrupt enable (no effect in output mode) */
    auth_ard_io_exp_isr_t io_exp_BIO2_ISR_Enabled; /*!< BIO2 interrupt enable (no effect in output mode) */

    /* Input Latch Configuration (P0-P3) */
    auth_ard_io_exp_isr_t io_exp_AIO1_InputLatch_Enabled; /*!< AIO1 input latch enable (no effect in output mode) */
    auth_ard_io_exp_isr_t io_exp_AIO2_InputLatch_Enabled; /*!< AIO2 input latch enable (no effect in output mode) */
    auth_ard_io_exp_isr_t io_exp_BIO1_InputLatch_Enabled; /*!< BIO1 input latch enable (no effect in output mode) */
    auth_ard_io_exp_isr_t io_exp_BIO2_InputLatch_Enabled; /*!< BIO2 input latch enable (no effect in output mode) */
} auth_ard_io_exp_config_t;

/* ************************************************************************** */
/* API Function Prototypes                                                    */
/* ************************************************************************** */

#if defined(__cplusplus)
extern "C" {
#endif

/*!
 * @name Initialization and Configuration
 * @{
 */

/*!
 * @brief Initializes the Auth ARD PCAL6408A I2C I/O expander configuration structure with default values.
 *
 * This function sets default configuration values for all I/O pins:
 * - P0-P3 (AIO1, AIO2, BIO1, BIO2): Configured as inputs with inverted polarity
 * - P4-P7 (Power switches and LEDs): Configured as outputs in OFF state
 * - All interrupts and input latches: Disabled
 *
 * @param io_expander_config Pointer to the configuration structure to initialize.
 */
void auth_ard_IO_ExpanderGetDefaultConfig(auth_ard_io_exp_config_t *io_expander_config);

/*!
 * @brief Initializes the Auth ARD PCAL6408A I2C I/O port expander.
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
 * @note Pins P4–P7 are always configured as outputs. Pins P0–P3 are configured based on
 *       the direction settings in the configuration structure.
 *
 * @note The following PCAL6408A ports, when configured as inputs, can trigger an interrupt:
 *       - P3: EVK A IO1 or button AIO1
 *       - P2: EVK A IO2 or button AIO2
 *       - P1: EVK B/C/D IO1 or button BIO1
 *       - P0: EVK B/C/D IO2 or button BIO2
 *
 * @param io_expander_config Configuration structure containing I/O directions,
 *        initial output states, input polarity inversion and input interrupt
 *        settings for the corresponding I/O pin of the expander.
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was received successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_IO_ExpanderInit(auth_ard_io_exp_config_t io_expander_config);

/*! @} */

/*!
 * @name Power Control Functions
 * @{
 */

/*!
 * @brief Controls the state of EVK A Power Switch (P-MOSFET Q2) connected via PCAL6408A I2C I/O expander (port pin P5).
 *
 * @param switch_value Desired Power state:
 *                     - kAuth_ARD_Off: Turn off EVK A Power Supply
 *                     - kAuth_ARD_On: Turn on EVK A Power Supply
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was written successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_EVK_A_Power(auth_ard_io_exp_output_state_t switch_value);

/*!
 * @brief Controls the state of EVK B/C/D Power Switch (P-MOSFET Q1) connected via PCAL6408A I2C I/O expander (port pin P4).
 *
 * @param switch_value Desired Power state:
 *                     - kAuth_ARD_Off: Turn off EVK B/C/D Power Supply
 *                     - kAuth_ARD_On: Turn on EVK B/C/D Power Supply
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was written successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_EVK_B_Power(auth_ard_io_exp_output_state_t switch_value);

/*! @} */

/*!
 * @name LED Control Functions
 * @{
 */

/*!
 * @brief Controls the state of LED1 connected via the PCAL6408A I2C I/O expander (port pin P6).
 *
 * @param led_value Desired LED state:
 *                  - kAuth_ARD_Off: Turn off LED1
 *                  - kAuth_ARD_On: Turn on LED1
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was written successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_LED1(auth_ard_io_exp_output_state_t led_value);

/*!
 * @brief Controls the state of LED2 connected via the PCAL6408A I2C I/O expander (port pin P7).
 *
 * @param led_value Desired LED state:
 *                  - kAuth_ARD_Off: Turn off LED2
 *                  - kAuth_ARD_On: Turn on LED2
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was written successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_LED2(auth_ard_io_exp_output_state_t led_value);

/*! @} */

/*!
 * @name AIO Output Control Functions
 * @{
 */

/*!
 * @brief Sets the state of AIO1 (PCAL6408A I2C I/O expander port pin P3).
 *
 * @note Ensure that the AIO1 port direction is configured as output before calling this function.
 *
 * @param output_value Desired output state:
 *                     - kAuth_ARD_Low: Sets AIO1 low (turn on LED '0', turn off LED '1')
 *                     - kAuth_ARD_High: Sets AIO1 high (turn off LED '0', turn on LED '1')
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was written successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_AIO1_Out(auth_ard_io_exp_output_state_t output_value);

/*!
 * @brief Sets the state of AIO2 (PCAL6408A I2C I/O expander port pin P2).
 *
 * @note Ensure that the AIO2 port direction is configured as output before calling this function.
 *
 * @param output_value Desired output state:
 *                     - kAuth_ARD_Low: Sets AIO2 low (turn on LED '0', turn off LED '1')
 *                     - kAuth_ARD_High: Sets AIO2 high (turn off LED '0', turn on LED '1')
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was written successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_AIO2_Out(auth_ard_io_exp_output_state_t output_value);

/*! @} */

/*!
 * @name BIO Output Control Functions
 * @{
 */

/*!
 * @brief Sets the state of BIO1 (PCAL6408A I2C I/O expander port pin P1).
 *
 * @note Ensure that the BIO1 port direction is configured as output before calling this function.
 *
 * @param output_value Desired output state:
 *                     - kAuth_ARD_Low: Sets BIO1 low (turn on LED '0', turn off LED '1')
 *                     - kAuth_ARD_High: Sets BIO1 high (turn off LED '0', turn on LED '1')
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was written successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_BIO1_Out(auth_ard_io_exp_output_state_t output_value);

/*!
 * @brief Sets the state of BIO2 (PCAL6408A I2C I/O expander port pin P0).
 *
 * @note Ensure that the BIO2 port direction is configured as output before calling this function.
 *
 * @param output_value Desired output state:
 *                     - kAuth_ARD_Low: Sets BIO2 low (turn on LED '0', turn off LED '1')
 *                     - kAuth_ARD_High: Sets BIO2 high (turn off LED '0', turn on LED '1')
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was written successfully.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_BIO2_Out(auth_ard_io_exp_output_state_t output_value);

/*! @} */

/*!
 * @name Input and Status Read Functions
 * @{
 */

/*!
 * @brief Reads the current value from the Auth ARD PCAL6408A I2C I/O port expander Input Port Register (P0 to P7).
 *
 * @note An active PCAL6408A I2C I/O port expander interrupt is cleared when the Input Port Register is read.
 *
 * @param input_value Pointer to a variable where the input port value will be stored.
 *
 * @return status_t Status code indicating success or failure of the operation.
 * @retval #kStatus_Success Data was read successfully.
 * @retval #kStatus_InvalidArgument input_value pointer is NULL.
 * @retval #kStatus_LPI2C_Busy Another master is currently utilizing the bus.
 * @retval #kStatus_LPI2C_Nak The slave device sent a NAK in response to a byte.
 * @retval #kStatus_LPI2C_FifoError FIFO under run or overrun.
 * @retval #kStatus_LPI2C_ArbitrationLost Arbitration lost error.
 * @retval #kStatus_LPI2C_PinLowTimeout SCL or SDA were held low longer than the timeout.
 */
status_t auth_ard_ReadInputPort(uint8_t *input_value);

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
status_t auth_ard_ReadIsrStatus(uint8_t *isr_status);

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif
