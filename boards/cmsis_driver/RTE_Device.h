/*
 * Copyright 2025 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _RTE_DEVICE_H
#define _RTE_DEVICE_H

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#include "pin_mux.h"

/* I2C Select, I2C0 -I2C7*/
/* User needs to provide the implementation of I2CX_GetFreq/I2CX_InitPins/I2CX_DeinitPins for the enabled I2C instance.
 */
#if defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947 == 1)
#define RTE_I2C2 1
#define RTE_I2C2_DMA_EN 0
#define RTE_I2C3 1
#define RTE_I2C3_DMA_EN 0
#define RTE_GPIO_PORT0 1
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153 == 1)
#define RTE_I2C0 1
#define RTE_I2C0_DMA_EN 0
#define RTE_GPIO_PORT2 1
#endif
#endif /* _RTE_DEVICE_H */