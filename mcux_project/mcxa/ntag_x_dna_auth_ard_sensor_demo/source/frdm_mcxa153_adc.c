/*
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "frdm_mcxa153_adc.h"
#include <math.h>

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/** @brief Full-scale ADC value (12-bit resolution). */
#define LPADC_FULL_RANGE   4095U

/** @brief Right shift value to convert ADC result to 12-bit range. */
#define LPADC_RESULT_SHIFT 3U

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/** @brief LPADC configuration structure. */
static lpadc_config_t mLpadcConfigStruct;

/** @brief LPADC conversion trigger configuration structure. */
static lpadc_conv_trigger_config_t mLpadcTriggerConfigStruct;

/** @brief LPADC conversion command configuration structure. */
static lpadc_conv_command_config_t mLpadcCommandConfigStruct;

/** @brief LPADC conversion result structure. */
static lpadc_conv_result_t mLpadcResultConfigStruct;

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

void adc_Init(void)
{
    /* Configure ADC clock: divide by 1 and attach FRO12M clock source */
    CLOCK_SetClockDiv(kCLOCK_DivADC0, 1u);
    CLOCK_AttachClk(kFRO12M_to_ADC0);

    /* Get default LPADC configuration and customize settings */
    LPADC_GetDefaultConfig(&mLpadcConfigStruct);
    mLpadcConfigStruct.enableAnalogPreliminary = true;
    mLpadcConfigStruct.referenceVoltageSource  = DEMO_LPADC_VREF_SOURCE;
    mLpadcConfigStruct.conversionAverageMode   = kLPADC_ConversionAverage128;
    LPADC_Init(DEMO_LPADC_BASE, &mLpadcConfigStruct);

    /* Perform offset calibration to automatically update OFSTRIM register */
    LPADC_DoOffsetCalibration(DEMO_LPADC_BASE);

    /* Perform auto calibration for gain error and linearity error correction */
    LPADC_DoAutoCalibration(DEMO_LPADC_BASE);

    /* Configure conversion command for the specified channel */
    LPADC_GetDefaultConvCommandConfig(&mLpadcCommandConfigStruct);
    mLpadcCommandConfigStruct.channelNumber = DEMO_LPADC_USER_CHANNEL;
    LPADC_SetConvCommandConfig(DEMO_LPADC_BASE, DEMO_LPADC_USER_CMDID, &mLpadcCommandConfigStruct);

    /* Configure software trigger (trigger0) for conversion command */
    LPADC_GetDefaultConvTriggerConfig(&mLpadcTriggerConfigStruct);
    mLpadcTriggerConfigStruct.targetCommandId       = DEMO_LPADC_USER_CMDID;
    mLpadcTriggerConfigStruct.enableHardwareTrigger = false;
    LPADC_SetConvTriggerConfig(DEMO_LPADC_BASE, 0U, &mLpadcTriggerConfigStruct);
}

uint16_t adc_ReadValue(void)
{
    /* Trigger ADC conversion via software trigger (trigger0 mask = 1U) */
    LPADC_DoSoftwareTrigger(DEMO_LPADC_BASE, 1U);

    /* Wait for conversion result to be available */
    while (!LPADC_GetConvResult(DEMO_LPADC_BASE, &mLpadcResultConfigStruct))
    {
    }

    /* Return 12-bit ADC value by shifting the result */
    return (uint16_t)((mLpadcResultConfigStruct.convValue) >> LPADC_RESULT_SHIFT);
}

uint8_t auth_ard_Slider_ReadValue(void)
{
    /* Read raw ADC value from the slider input */
    uint16_t adcValue = adc_ReadValue();

    /* Convert ADC value to percentage (0-100) and round to nearest integer */
    uint8_t sliderValue = (uint8_t)roundf((adcValue * 100.0f) / LPADC_FULL_RANGE);

    return sliderValue;
}
