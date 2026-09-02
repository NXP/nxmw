/*
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file frdm_mcxa153_adc.h
 * @brief ADC driver for FRDM-MCXA153 board slider input.
 *
 * This header provides function declarations for initializing and reading
 * the LPADC peripheral connected to the slider potentiometer on the
 * FRDM-MCXA153 board.
 */

#ifndef FRDM_MCXA153_ADC_H_
#define FRDM_MCXA153_ADC_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "fsl_debug_console.h"
#include "board.h"
#include "app.h"
#include "fsl_lpadc.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/** @brief LPADC peripheral base address. */
#define DEMO_LPADC_BASE                  ADC0

/** @brief ADC channel number connected to the slider potentiometer. */
#define DEMO_LPADC_USER_CHANNEL          8U

/** @brief ADC command ID used for conversion. */
#define DEMO_LPADC_USER_CMDID            1U

/** @brief ADC reference voltage source (VDDA). */
#define DEMO_LPADC_VREF_SOURCE           kLPADC_ReferenceVoltageAlt3

/** @brief Enable offset calibration during initialization. */
#define DEMO_LPADC_DO_OFFSET_CALIBRATION true

/** @brief Enable high resolution mode for ADC conversions. */
#define DEMO_LPADC_USE_HIGH_RESOLUTION   true

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/**
 * @brief Initialize the LPADC peripheral for slider input.
 *
 * Configures the LPADC with the following settings:
 * - Clock source: FRO12M with divider = 1
 * - Reference voltage: VDDA
 * - Conversion averaging: 128 samples
 * - Performs offset and auto calibration
 * - Configures software trigger on trigger0
 *
 * @note This function must be called before adc_ReadValue() or auth_ard_Slider_ReadValue().
 */
void adc_Init(void);

/**
 * @brief Read raw ADC value from the slider potentiometer.
 *
 * Triggers a software conversion and waits for the result.
 * The returned value is a 12-bit ADC reading (0-4095).
 *
 * @return 12-bit ADC conversion result (0-4095).
 *
 * @note This function blocks until the conversion is complete.
 */
uint16_t adc_ReadValue(void);

/**
 * @brief Read slider position as a percentage value.
 *
 * Reads the raw ADC value and converts it to a percentage (0-100)
 * representing the slider position.
 *
 * @return Slider position as percentage (0-100).
 *
 * @note This function blocks until the ADC conversion is complete.
 */
uint8_t auth_ard_Slider_ReadValue(void);

#endif /* FRDM_MCXA153_ADC_H_ */
