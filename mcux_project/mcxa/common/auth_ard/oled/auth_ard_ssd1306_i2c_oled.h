/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef OLED_AUTH_ARD_SSD1306_I2C_OLED_H_
#define OLED_AUTH_ARD_SSD1306_I2C_OLED_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "U8g2.h"
#include "auth_ard_u8x8_cb.h"

/* ************************************************************************** */
/* API Functions                                                              */
/* ************************************************************************** */

void auth_ard_OLED_ClearDisplay();

/*!
 * @brief Initializes the OLED display.
 *
 * This function sets up the SSD1306 128x32 OLED display parameters using the
 * u8g2 library and wakes it from sleep mode.
 */
void auth_ard_OLED_Init(void);

/*!
 * @brief Clears the screen buffer and the OLED display.
 *
 * This function clears both the internal buffer and the physical display.
 */
void auth_ard_OLED_ClearDisplay(void);

/*!
 * @brief Sets the font for the OLED display.
 *
 * This function configures the font to be used for subsequent text rendering
 * operations on the OLED display.
 *
 * @param font Pointer to the font to be used (u8g2 font format)
 */
void auth_ard_OLED_SetFont(const uint8_t *font);

/*!
 * @brief Prints a string at the specified position on the OLED display.
 *
 * This function draws a null-terminated string at the given coordinates.
 * The position (x, y) represents the lower left corner of the first character.
 *
 * @param x Horizontal position in pixels (lower left corner of first character)
 * @param y Vertical position in pixels (lower left corner of first character)
 * @param str Pointer to the null-terminated string to be printed
 */
void auth_ard_OLED_Print(u8g2_uint_t x, u8g2_uint_t y, const char *str);

/*!
 * @brief Prints a formatted string at the specified position on the OLED display.
 *
 * This function formats and draws a string at the given coordinates using
 * printf-style formatting. The position (x, y) represents the lower left corner
 * of the first character.
 *
 * @param x Horizontal position in pixels (lower left corner of first character)
 * @param y Vertical position in pixels (lower left corner of first character)
 * @param format Format string (similar to printf)
 * @param ... Variable arguments for the format string
 */
void auth_ard_OLED_Printf(u8g2_uint_t x, u8g2_uint_t y, const char *format, ...);

/*!
 * @brief Draws a bitmap image at the specified position on the OLED display.
 *
 * This function renders a bitmap in XBM format starting from the given coordinates.
 * The position (x, y) represents the top-left corner of the bitmap.
 *
 * @param x Horizontal position in pixels (top-left corner of the bitmap)
 * @param y Vertical position in pixels (top-left corner of the bitmap)
 * @param w Width of the bitmap in pixels
 * @param h Height of the bitmap in pixels
 * @param bitmap Pointer to the bitmap data (in XBM format)
 */
void auth_ard_OLED_DrawBmp(u8g2_uint_t x, u8g2_uint_t y, u8g2_uint_t w, u8g2_uint_t h, const uint8_t *bitmap);

/*!
 * @brief Draws a bar graph on the OLED display.
 *
 * This function draws a horizontal bar graph with a frame at position (12, 24)
 * with dimensions 104x8 pixels. The filled portion is determined by the value parameter.
 *
 * @param value Length of the filled bar in pixels (0-100)
 */
void auth_ard_OLED_BarGraph(u8g2_uint_t value);

/*!
 * @brief Clears the internal display buffer.
 *
 * This function clears the internal buffer without updating the physical display.
 * Call auth_ard_OLED_UpdateDisplay() to apply changes to the screen.
 */
void auth_ard_OLED_ClearBuffer(void);

/*!
 * @brief Updates the OLED display with the current buffer content.
 *
 * This function sends the internal buffer to the physical display,
 * making all drawing operations visible on the screen.
 */
void auth_ard_OLED_UpdateDisplay(void);

#ifdef __cplusplus
} /* extern "c"*/
#endif

#endif /* OLED_AUTH_ARD_SSD1306_I2C_OLED_H_ */
