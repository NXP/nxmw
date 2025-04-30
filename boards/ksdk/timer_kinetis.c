/*
 *
 * Copyright 2016-2018,2020 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <sm_timer.h>
#include <stdint.h>

#include "board.h"
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if defined(__GNUC__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#endif

volatile uint32_t gtimer_kinetis_msticks; // counter for 1ms SysTicks

volatile int gusleep_delay;

#define CORR_FRDM_K64F_ARMCC (1000 / 100)
#define CORR_FRDM_K64F_ICCARM (1000 / 108)
#define CORR_FRDM_K64F_GCC (1000 / 100)

#if (defined(SSS_HAVE_HOST_EMBEDDED) && (SSS_HAVE_HOST_EMBEDDED))
#if defined(__ARMCC_VERSION)
#define CORRECTION_TOLERENCE CORR_FRDM_K64F_ARMCC
#elif defined(__ICCARM__)
#define CORRECTION_TOLERENCE CORR_FRDM_K64F_ICCARM
#else
#define CORRECTION_TOLERENCE CORR_FRDM_K64F_GCC
#endif
#endif // SSS_HAVE_HOST_EMBEDDED

//for ARM6 taken care at file level
// #ifdef __ARMCC_VERSION
// #pragma O0
// #endif

void sm_usleep(uint32_t microsec)
{
    gusleep_delay = microsec * CORRECTION_TOLERENCE;
    while (gusleep_delay--) {
        __NOP();
    }
}

#if defined(__GNUC__)
#pragma GCC pop_options
#endif
