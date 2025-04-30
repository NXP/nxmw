/* Copyright 2019 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "assert.h"

#define WEAK __attribute__ ((weak))

void vApplicationStackOverflowHook(void) {
    assert(0);
}

void vApplicationMallocFailedHook(void) {
    assert(0);
}

WEAK void vApplicationTickHook(void);

WEAK void vApplicationTickHook(void) {
}
