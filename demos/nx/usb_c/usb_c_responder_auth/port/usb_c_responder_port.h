/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_C_TX_PORT_H__
#define __USB_C_TX_PORT_H__

#include <sm_types.h>
#include <ex_sss_boot.h>
#include <fsl_sss_nx_apis.h>

#include "nxEnsure.h"

#ifndef SSS_MALLOC
#define SSS_MALLOC sm_malloc
#endif // SSS_MALLOC

#ifndef SSS_FREE
#define SSS_FREE sm_free
#endif // SSS_FREE

#endif // __USB_C_TX_PORT_H__
