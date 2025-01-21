/*
 *
 * Copyright 2019 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * ex_sss_ports.h:  Default ports being used in Examples and test cases
 *
 * $Date: Mar 10, 2019 $
 * $Author: ing05193 $
 * $Revision$
 */

#ifndef SSS_EX_INC_EX_SSS_PORTS_H_
#define SSS_EX_INC_EX_SSS_PORTS_H_

/* *****************************************************************************************************************
 * MACROS/Defines
 * ***************************************************************************************************************** */

#define EX_SSS_BOOT_SSS_PORT "EX_SSS_BOOT_SSS_PORT"

#ifdef __linux__
#define EX_SSS_BOOT_SSS_COMPORT_DEFAULT "/dev/ttyACM0"
#else
#define EX_SSS_BOOT_SSS_COMPORT_DEFAULT "\\\\.\\COM7"
#endif

#define EX_SSS_BOOT_SSS_JRCP_V1_PORT_DEFAULT "0.0.0.0:8040"

#define EX_SSS_BOOT_SSS_PCSC_READER_DEFAULT "NXP Semiconductors P71 T=0, T=1 Driver 0"

#endif /* SSS_EX_INC_EX_SSS_PORTS_H_ */
