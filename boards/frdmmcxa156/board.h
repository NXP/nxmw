/*
 * Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _BOARD_H_
#define _BOARD_H_

#include "clock_config.h"
#include "fsl_gpio.h"
#include "fsl_common.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*! @brief The board name */
#define BOARD_NAME "FRDM-MCXA156"
/*! @brief The manufacturer name */
#define MANUFACTURER_NAME "NXP"

/*! @brief The UART to use for debug messages. */
#define BOARD_DEBUG_UART_TYPE     kSerialPort_Uart
#define BOARD_DEBUG_UART_CLK_FREQ 12000000U

#ifndef BOARD_DEBUG_UART_BAUDRATE
#define BOARD_DEBUG_UART_BAUDRATE 115200U
#endif

#define BOARD_DEBUG_UART_BASEADDR   (uint32_t) LPUART0
#define BOARD_DEBUG_UART_INSTANCE   0U
#define BOARD_DEBUG_UART_CLK_ATTACH kFRO12M_to_LPUART0
#define BOARD_DEBUG_UART_RST        kLPUART0_RST_SHIFT_RSTn
#define BOARD_DEBUG_UART_CLKSRC     kCLOCK_LPUART0
#define BOARD_UART_IRQ_HANDLER      LPUART0_IRQHandler
#define BOARD_UART_IRQ              LPUART0_IRQn

/*! @brief GPIO for LED. */
#ifndef BOARD_LED_RED_GPIO
#define BOARD_LED_RED_GPIO GPIO3
#endif
#ifndef BOARD_LED_RED_GPIO_PIN
#define BOARD_LED_RED_GPIO_PIN 12U
#endif

#ifndef BOARD_LED_GREEN_GPIO
#define BOARD_LED_GREEN_GPIO GPIO3
#endif
#ifndef BOARD_LED_GREEN_GPIO_PIN
#define BOARD_LED_GREEN_GPIO_PIN 13U
#endif

#ifndef BOARD_LED_BLUE_GPIO
#define BOARD_LED_BLUE_GPIO GPIO3
#endif
#ifndef BOARD_LED_BLUE_GPIO_PIN
#define BOARD_LED_BLUE_GPIO_PIN 0U
#endif

/* GPIO pins declaration */
#ifndef BOARD_P2_12_GPIO_PIN
#define BOARD_P2_12_GPIO_PIN 12U
#endif

#ifndef BOARD_P2_16_GPIO_PIN
#define BOARD_P2_16_GPIO_PIN 16U
#endif

#define BOARD_GPIO_PIN_IO1      BOARD_P2_12_GPIO_PIN
#define BOARD_GPIO_PIN_IO2      BOARD_P2_16_GPIO_PIN
#define INIT_GPIO_PIN(pin,cfg)  GPIO_PinInit(GPIO2, (pin), (cfg))
#define SET_GPIO_PIN(pin)       GPIO_PortSet(GPIO2, 1U << (pin))
#define CLEAR_GPIO_PIN(pin)     GPIO_PortClear(GPIO2, 1U << (pin))
#define TOGGLE_GPIO_PIN(pin)    GPIO_PortToggle(GPIO2, 1U << (pin))
#define READ_GPIO_PIN(pin)      (uint8_t)GPIO_PinRead(GPIO2, (pin))

/*! @brief GPIO for SW. */
#ifndef BOARD_SW2_GPIO
#define BOARD_SW2_GPIO GPIO1
#endif
#ifndef BOARD_SW2_GPIO_PIN
#define BOARD_SW2_GPIO_PIN 7U
#endif
#define BOARD_SW2_NAME        "SW2"
#define BOARD_SW2_IRQ         GPIO1_IRQn
#define BOARD_SW2_IRQ_HANDLER GPIO1_IRQHandler

#ifndef BOARD_SW3_GPIO
#define BOARD_SW3_GPIO GPIO0
#endif
#ifndef BOARD_SW3_GPIO_PIN
#define BOARD_SW3_GPIO_PIN 6U
#endif
#define BOARD_SW3_NAME        "SW3"
#define BOARD_SW3_IRQ         GPIO0_IRQn
#define BOARD_SW3_IRQ_HANDLER GPIO0_IRQHandler

/* Board LED color mapping */
#define LOGIC_LED_ON  0U
#define LOGIC_LED_OFF 1U

#define LED_RED_INIT(output)                                           \
    GPIO_PinWrite(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PIN, output); \
    BOARD_LED_RED_GPIO->PDDR |= (1U << BOARD_LED_RED_GPIO_PIN)               /*!< Enable target LED_RED */
#define LED_RED_ON() \
    GPIO_PinWrite(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PIN, LOGIC_LED_ON)  /*!< Turn on target LED_RED */
#define LED_RED_OFF() \
    GPIO_PinWrite(BOARD_LED_RED_GPIO, BOARD_LED_RED_GPIO_PIN, LOGIC_LED_OFF) /*!< Turn off target LED_RED */
#define LED_RED_TOGGLE() \
    GPIO_PortToggle(BOARD_LED_RED_GPIO, 1U << BOARD_LED_RED_GPIO_PIN)        /*!< Toggle on target LED_RED */

#define LED_GREEN_INIT(output)                                             \
    GPIO_PinWrite(BOARD_LED_GREEN_GPIO, BOARD_LED_GREEN_GPIO_PIN, output); \
    BOARD_LED_GREEN_GPIO->PDDR |= (1U << BOARD_LED_GREEN_GPIO_PIN)             /*!< Enable target LED_GREEN */
#define LED_GREEN_ON() \
    GPIO_PinWrite(BOARD_LED_RED_GPIO, BOARD_LED_GREEN_GPIO_PIN, LOGIC_LED_ON)  /*!< Turn on target LED_GREEN */
#define LED_GREEN_OFF() \
    GPIO_PinWrite(BOARD_LED_RED_GPIO, BOARD_LED_GREEN_GPIO_PIN, LOGIC_LED_OFF) /*!< Turn off target LED_GREEN */
#define LED_GREEN_TOGGLE() \
    GPIO_PortToggle(BOARD_LED_GREEN_GPIO, 1U << BOARD_LED_GREEN_GPIO_PIN)      /*!< Toggle on target LED_GREEN */

#define LED_BLUE_INIT(output)                                            \
    GPIO_PinWrite(BOARD_LED_BLUE_GPIO, BOARD_LED_BLUE_GPIO_PIN, output); \
    BOARD_LED_BLUE_GPIO->PDDR |= (1U << BOARD_LED_BLUE_GPIO_PIN)              /*!< Enable target LED_BLUE */
#define LED_BLUE_ON() \
    GPIO_PinWrite(BOARD_LED_RED_GPIO, BOARD_LED_BLUE_GPIO_PIN, LOGIC_LED_ON)  /*!< Turn on target LED_BLUE */
#define LED_BLUE_OFF() \
    GPIO_PinWrite(BOARD_LED_RED_GPIO, BOARD_LED_BLUE_GPIO_PIN, LOGIC_LED_OFF) /*!< Turn off target LED_BLUE */
#define LED_BLUE_TOGGLE() \
    GPIO_PortToggle(BOARD_LED_BLUE_GPIO, 1U << BOARD_LED_BLUE_GPIO_PIN)       /*!< Toggle on target LED_BLUE */

/*******************************************************************************
 * API
 ******************************************************************************/
void BOARD_InitDebugConsole(void);

#endif /* _BOARD_H_ */
