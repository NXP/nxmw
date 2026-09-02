/*
 * Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <app_auth_ard.h>

/*******************************************************************************
 * Variables
 ******************************************************************************/
volatile bool g_auth_ard_NdefRead_ISR_Flag = false;

/*******************************************************************************
 * Code
 ******************************************************************************/

void AUTH_ARD_IO_EXP_IRQ_HANDLER(void)
{
	status_t result;
	uint8_t auth_ard_io_exp_input_port_value;

	/* Clear the GPIO interrupt flag for the I/O expander interrupt pin */
	GPIO_GpioClearInterruptFlags(BOARD_INITPINS_AUTH_ARD_IO_EXP_INT_GPIO, 1U << BOARD_INITPINS_AUTH_ARD_IO_EXP_INT_GPIO_PIN);

	/* Reading the Input Port register clears the Auth ARD I/O port expander interrupt */
	result = auth_ard_ReadInputPort(&auth_ard_io_exp_input_port_value);
	if (kStatus_Success == result)
	{
		/* Check if the I/O expander interrupt was triggered by BIO2 rising edge.
		 * A rising edge on BIO2 indicates that the NTAG X DNA has toggled GPIO2,
		 * signaling that an NFC-enabled phone has initiated an NDEF file read. */
		if ((auth_ard_io_exp_input_port_value & AUTH_ARD_BIO2_MASK) == kAuth_ARD_High)
		{
			/* Set the global NDEF read ISR flag.
			 * The main application loop monitors this flag and processes
			 * the NDEF read event outside the interrupt context. */
			g_auth_ard_NdefRead_ISR_Flag = true;
		}
	}
}
