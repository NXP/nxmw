/* Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
/* For MCU Integration */

#define BOARD_InitHardware() \
    BOARD_InitPins();        \
    BOARD_BootClockRUN();    \
    BOARD_InitDebugConsole()
