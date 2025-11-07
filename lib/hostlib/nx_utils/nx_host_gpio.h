/*
*
* Copyright 2023-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef _NX_HOST_GPIO_H_
#define _NX_HOST_GPIO_H_

#include "sm_types.h"
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

/** MCU GPIO direction, input or output */
typedef enum
{
    NX_HOSTGPIOInput  = 0x00,
    NX_HOSTGPIOOutput = 0x01,
} Nx_host_mcu_gpio_direction_ctl_t;

#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM) || \
    defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
/** MCU GPIO pins, PTB2 or PTB3 */
typedef enum
{
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    NX_HOSTGPIO_I01 = 0x01, //VCOM MCU PIN
    NX_HOSTGPIO_I02 = 0x02, //VCOM MCU PIN
#endif
#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0) && (SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    NX_HOSTGPIO_PTB2   = 0x02, //K64F PTB2 PIN
    NX_HOSTGPIO_PTB3   = 0x03, //K64F PTB3 PIN
    NX_HOSTGPIO_PIO1_5 = 0x05, //LPC PIO1_5 PIN
    NX_HOSTGPIO_PIO1_8 = 0x08, //LPC PIO1_8 PIN
#endif
} Nx_host_mcu_gpio_pins_ctl_t;
/*MCU GPIO Port, LPC55s69 board*/
#define NX_HOSTPGIO_PORT1 0x01
#endif

#if defined(SSS_HAVE_HOST_RASPBIAN)
typedef enum
{
    NX_HOST_RPI_INPUT_PIN_GPIO1 = 14,
    NX_HOST_RPI_INPUT_PIN_GPIO2 = 15,
} Nx_host_rpi_gpio_pins_ctl_t;
#endif

/** MCU GPIO Read outputs, Low or High */
typedef enum
{
    NX_HOSTGPIO_Read_Low  = 0x00,
    NX_HOSTGPIO_Read_High = 0x01,
} Nx_host_mcu_gpio_readOutput_ctl_t;

#ifdef __cplusplus
extern "C" {
#endif

U16 nx_host_GPIOInit(void *conn_ctx, U8 gpioPIN, U8 setInOutDir);
U16 nx_host_GPIOSet(void *conn_ctx, U8 gpioPIN);
U16 nx_host_GPIOClear(void *conn_ctx, U8 gpioPIN);
U16 nx_host_GPIOToggle(void *conn_ctx, U8 gpioPIN);
U16 nx_host_GPIORead(void *conn_ctx, U8 gpioPIN, U8 *resp, U16 *respLen);
U16 nx_host_GPIOClose(void *conn_ctx, U8 gpioPIN);
#ifdef __cplusplus
}
#endif

#endif // _NX_HOST_GPIO_H_