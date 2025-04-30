/**
* @file ledHandler.c
* @author NXP Semiconductors
* @version 1.0
* @par License
*
* Copyright 2017-2018, 2020, 2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*
* @par Description
* Led Handler
*/

#include "sm_types.h"
#include "nxLog_msg.h"
#include "ledHandler.h"

void led_handler(ledColor_t led, ledState_t state)
{
    switch (led) {
    case RED:
        if (state == LED_ON) {
            LED_RED_ON();
        }
        else if (state == LED_OFF) {
            LED_RED_OFF();
        }
        else /*State is an enum so safely making use of else*/
        {
            LED_RED_TOGGLE();
        }
        break;
    case GREEN:
        if (state == LED_ON) {
            LED_GREEN_ON();
        }
        else if (state == LED_OFF) {
            LED_GREEN_OFF();
        }
        else /*State is an enum so safely making use of else*/
        {
            LED_GREEN_TOGGLE();
        }
        break;
    case BLUE:
        if (state == LED_ON) {
            LED_BLUE_ON();
        }
        else if (state == LED_OFF) {
            LED_BLUE_OFF();
        }
        else /*State is an enum so safely making use of else*/
        {
            LED_BLUE_TOGGLE();
        }
        break;
    default:
        LOG_W("wrong LED \n");
    }
}
