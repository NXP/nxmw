/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include "board.h"
#include "fsl_common_arm.h"
#include "peripherals.h"
#include "pin_mux.h"
#include "fsl_lpi2c.h"
#include "fsl_gpio.h"
#include "clock_config.h"
#include "fsl_debug_console.h"
#include "platform.h"
#include "app_auth_ard.h"
#include "app_provision_ntag_x_dna.h"

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */


/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/**
 * @brief Main function
 *
*    This example provisions an NTAG X DNA tag to support the
 *   NTAG X DNA AUTH-ARD Shield Sensor Demo.
 *
 *          The provisioning sequence performed by this example:
 *            1. Opens a symmetric authenticated session with the NTAG X DNA.
 *            2. Updates the ECC key policy to enable ECC-based SDM signing.
 *            3. Builds and writes an NDEF URI record containing SDM mirror
 *               token placeholders for UID, read counter, and signature.
 *            4. Configures the NDEF file SDM settings, including mirror
 *               offsets for UID, read counter, and signature fields.
 *            5. Updates the CC file to grant read/write access.
 *            6. Configures GPIO2 in NfcPausefileOut mode to allow the host
 *               MCU to update sensor data before the tag responds.
 *            7. Reads and logs the device UID for NTAG service registration.
 *            8. Reads and logs the application certificate for NTAG service
 *               registration.
 *            9. Closes the authenticated session.
 *
 *          Provisioning result is displayed on the AUTH-ARD OLED screen.
 * 
 *         Warning This example is only for demonstration purpose.
 *                 Maintaining and provisioning the keys/files should be done 
*                  in a secure way.
 */
int main(void)
{
    sss_status_t sss_status = kStatus_SSS_Fail;

    /* ---------------------------------------------------------------------- */
    /* Hardware Initialization                                                 */
    /* ---------------------------------------------------------------------- */

    /* Initialize the FRDM-MCXA153 board and the NX middleware stack */
    platform_boot_direct();

    /* Initialize the AUTH-ARD I2C bus interface */
    app_auth_ard_i2c_Interface_Init(LPI2C_BAUDRATE);

    /* Initialize the AUTH-ARD I/O port expander */
    app_auth_ard_io_expander_Init();

    /* ---------------------------------------------------------------------- */
    /* AUTH-ARD OLED Display Initialization                                   */
    /* ---------------------------------------------------------------------- */

    /* Initialize the OLED display and set the default font */
    auth_ard_OLED_Init();
    auth_ard_OLED_SetFont(u8g2_font_profont15_mf);

    /* Show provisioning start message on the OLED */
    auth_ard_OLED_Print(5, 12, "NTAG X DNA:");
    auth_ard_OLED_Print(5, 28, "Provision");
    auth_ard_OLED_UpdateDisplay();

    /* ---------------------------------------------------------------------- */
    /* NTAG X DNA Provisioning                                                */
    /* ---------------------------------------------------------------------- */

    /*
     * Run the full NTAG X DNA SDM provisioning sequence.
     * On success, the tag is configured for Secure Dynamic Messaging with:
     *   - ECC-based SDM signing enabled.
     *   - NDEF URI record with UID, read counter, and signature mirror tokens.
     *   - GPIO2 configured in NfcPausefileOut mode.
     * See app_provision_ntag_x_dna.h / app_provision_ntag_x_dna.c for details.
     */
    sss_status = provision_ntag_x_dna();

    /* ---------------------------------------------------------------------- */
    /* Display Provisioning Result on OLED                                    */
    /* ---------------------------------------------------------------------- */
    if (kStatus_SSS_Success == sss_status)
    {
    	/* Provisioning succeeded: confirm success on the OLED display */
    	auth_ard_OLED_Print(5, 12, "NTAG X DNA:");
    	auth_ard_OLED_Print(5, 28, "Provision OK");

        LOG_I("NTAG X DNA AUTH-ARD Shield Trusted Sensor Provisioning Demo Success !!!...");
    }
    else 
    {
        /* Provisioning failed: report error on the OLED display */
        auth_ard_OLED_Print(5, 12, "NTAG X DNA:");
        auth_ard_OLED_Print(5, 28, "Provision ERROR");
        LOG_E("NTAG X DNA AUTH-ARD Shield Trusted Sensor Provisioning Demo Failed !!!...");

    }

    auth_ard_OLED_UpdateDisplay();

    return 0;
}
