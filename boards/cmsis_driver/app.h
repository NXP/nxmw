/*
 * Copyright 2025 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef _APP_H_
#define _APP_H_
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include "fsl_gpio_cmsis.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*${macro:start}*/

#define SET_GPIO_PIN_INPUT ARM_GPIO_INPUT
#define SET_GPIO_PIN_OUTPUT ARM_GPIO_OUTPUT
#define SET_GPIO_HIGH 1u
#define SET_GPIO_LOW 0u

#if defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947 == 1)
#define I2C_DEVICE_TYPE LPI2C_Type

#define I2C_MASTER_BASE Driver_I2C2
#define I2C_DEVICE_HANDLE ((LPI2C_Type *)(LPI2C2_BASE))
#define LPI2C_CLOCK_FREQUENCY CLOCK_GetLPFlexCommClkFreq(2u)

#define I2C_MASTER_I2C3 Driver_I2C3
#define AX_I2C3M ((LPI2C_Type *)(LPI2C3_BASE))
#define LPI2C3_CLOCK_FREQUENCY CLOCK_GetLPFlexCommClkFreq(3u)

#define EXAMPLE_GPIO_INTERFACE Driver_GPIO_PORT0
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153 == 1)
#define I2C_DEVICE_TYPE LPI2C_Type

#define I2C_DEVICE_HANDLE ((LPI2C_Type *)(LPI2C0_BASE))
#define I2C_MASTER_BASE Driver_I2C0
#define LPI2C_CLOCK_FREQUENCY CLOCK_GetLpi2cClkFreq()
//Dummy Decleartion
#define I2C_MASTER_I2C3 Driver_I2C0
#define AX_I2C3M NULL

#define EXAMPLE_GPIO_INTERFACE Driver_GPIO_PORT2
#else
#error "Unsupported host configuration for I2C device"
#endif

/*${macro:end}*/

#endif /* _APP_H_ */
