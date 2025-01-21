/**
 * @file app_boot.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par License
 *
 * Copyright 2017 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * @par Description
 * Implementation of the App booting time initilization functions
 */

#include "sm_api.h"

/**
 * Boot up of the application.  Configure clocks/pin/etc. where applicable on
 * platform. For most systems these decisions have to be made as early as
 * possible during boot.
 *
 * For many systems like linux/windows these would translate to an almost empty
 * call. For other embedded platforms this would do HW initialization.
 *
 * @return     0 on success.
 */
extern int app_boot_Init(void);

/**
 * For Freerots crypto init function to be called after task creation
 */
extern int app_boot_Init_RTOS(void);
/**
 * Connect to Secure Authenticator based on the pre-compiled selection of
 * Communication layer.
 *
 * @param[out] pCommState        Pointer where the communication state is updated.
 * @param[in]  pConnectionParam  Can be null where connection is I2C/etc. on the
 *                               same board.  For remote connection this would
 *                               be name of IpAddress/Server Name : Port in case
 *                               of Socket connection or COM PORT in case of
 *                               VCOM Connection.
 *
 * @return     0 on success.
 */
extern int app_boot_Connect(
    SmCommState_t* pCommState, const char* pConnectionParam);

/**
 * SET LEDs for the stauts.
 *
 * @parm[in] status 1 => Pass. 0 ==> Failed.
 */
extern void app_test_status(U8 result);
