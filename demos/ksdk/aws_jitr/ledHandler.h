/**
 * @file ledHander.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017-2018, 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * @par Description
 * LED Handler
 */

#ifndef SOURCES_LED_HANDLER_H_
#define SOURCES_LED_HANDLER_H_

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
/* *****************************************************************************************************************
 *   Includes
 * ***************************************************************************************************************** */
#include <sm_types.h>
#include <stdio.h>

#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
#include "board.h"
#else
#define LED_RED_ON() LOG_I("* RED LED ON\n");

#define LED_RED_OFF() LOG_I("* RED LED OFF\n");

#define LED_RED_TOGGLE() LOG_I("* RED LED TOGGLE\n");

#define LED_GREEN_ON() LOG_I("* GREEN LED ON\n");

#define LED_GREEN_OFF() LOG_I("* GREEN LED OFF\n");

#define LED_GREEN_TOGGLE() LOG_I("* GREEN LED TOGGLE\n");

#define LED_BLUE_ON() LOG_I("* BLUE LED ON\n");

#define LED_BLUE_OFF() LOG_I("* BLUE LED OFF\n");

#define LED_BLUE_TOGGLE() LOG_I("* BLUE LED TOGGLE\n\n");
#endif // !SSS_HAVE_HOST_FRDMK64

typedef enum LED_COLOR
{
    LED_INVALID,
    RED,
    GREEN,
    BLUE
} ledColor_t;
typedef enum LED_STATE
{
    LED_ON,
    LED_OFF,
    LED_TOGGLE
} ledState_t;
/*******************************************************************************
* Functions
******************************************************************************/
void led_handler(ledColor_t led, ledState_t state);

#endif /* SOURCES_LED_HANDLER_H_ */
