/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "auth_ard_u8x8_cb.h"

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

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
uint8_t auth_ard_u8x8_gpio_and_delay(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr)
{
    switch(msg)
    {
        case U8X8_MSG_GPIO_AND_DELAY_INIT:
            /* I2C and delay peripherals are already initialized */
            break;

        case U8X8_MSG_DELAY_MILLI:
            /* Delay in milliseconds */
            SDK_DelayAtLeastUs(arg_int * 1000U, CLOCK_GetFreq(kCLOCK_CoreSysClk));
            break;

        case U8X8_MSG_DELAY_100NANO:
            /* Delay 100 nanoseconds: minimum 1us delay applied */
            SDK_DelayAtLeastUs(1U, CLOCK_GetFreq(kCLOCK_CoreSysClk));
            break;

        case U8X8_MSG_DELAY_NANO:
            /* Delay in nanoseconds: minimum 1us delay applied */
            SDK_DelayAtLeastUs(1U, CLOCK_GetFreq(kCLOCK_CoreSysClk));
            break;

        case U8X8_MSG_DELAY_10MICRO:
            /* Delay 10 microseconds */
            SDK_DelayAtLeastUs(10U, CLOCK_GetFreq(kCLOCK_CoreSysClk));
            break;

        default:
            /* Unsupported message type */
            break;
    }
    return 1;
}

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
uint8_t auth_ard_u8x8_i2c(u8x8_t *u8x8, uint8_t msg, uint8_t arg_int, void *arg_ptr)
{
    /* u8g2/u8x8 will never send more than 32 bytes between
     * START_TRANSFER and END_TRANSFER */
    static uint8_t buffer[AUTH_ARD_U8X8_I2C_BUFFER_SIZE];
    static uint8_t buf_idx;
    uint8_t *data;

    switch(msg)
    {
        case U8X8_MSG_BYTE_INIT:
            /* I2C bus is already initialized */
            break;

        case U8X8_MSG_BYTE_SEND:
            /* Copy bytes to buffer */
            data = (uint8_t *)arg_ptr;
            while(arg_int > 0)
            {
                /* Guard against buffer overflow */
                if(buf_idx >= AUTH_ARD_U8X8_I2C_BUFFER_SIZE)
                {
                    return 0;
                }
                buffer[buf_idx++] = *data;
                data++;
                arg_int--;
            }
            break;

        case U8X8_MSG_BYTE_START_TRANSFER:
            /* Reset buffer index at start of transfer */
            buf_idx = 0;
            break;

        case U8X8_MSG_BYTE_END_TRANSFER:
            /* Send buffered data via I2C */
            I2C_Write(SSD_1306_I2C_ADDR, buffer, buf_idx);
            break;

        default:
            /* Unsupported message type */
            return 0;
    }
    return 1;
}
