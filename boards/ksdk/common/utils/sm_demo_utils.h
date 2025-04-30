/**
 * @file sm_demo_utils.h
 * @author NXP Semiconductors
 * @version 1.0
 * @par LICENSE
 *
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * @par Description
 * This file provides the interface to utility functions used by the example programs, not
 * the actual Host Library.
 * @par HISTORY
 * 1.0   20-mar-2018 : Initial version
 *
 */

#ifndef _sm_demo_utils_H_
#define _sm_demo_utils_H_

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * includes
 ******************************************************************************/
#if defined(LPC_ENET) || defined(LPC_WIFI)
#include "core_json.h"
#endif

/*******************************************************************************
 * DEFINITONS
 ******************************************************************************/

/*******************************************************************************
 * TYPES
 ******************************************************************************/

/*******************************************************************
* GLOBAL VARIABLES
*******************************************************************/

/*******************************************************************
* GLOBAL FUNCTION DECLARATIONS
*******************************************************************/

/* Init network and provide a 18 bit buffer to create a
 * unique-enough MAC and avoid MAC Clash.
 *
 * The 18 byte buffer is extracted from the A7x IC.
 */
extern void BOARD_InitNetwork_MAC(const unsigned char buffer[18]);

#ifdef __cplusplus
}
#endif

#endif /*_sm_demo_utils_H_*/
