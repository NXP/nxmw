/*
 *
 * Copyright 2024-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "platform.h"

extern void platform_boot_direct_impl();
extern int plaform_init_hardware_impl();
extern void platform_init_network_impl(const uint8_t *identifier);
extern void platform_success_indicator_impl();
extern void platform_failure_indicator_impl();

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */
int platform_boot_direct()
{
    int ret = 1;
    platform_boot_direct_impl();

    ret = sm_initSleep();
    if (0 != ret) {
        goto exit;
    }
exit:
    return ret;
}

int platform_init_hardware()
{
    int ret = 1;
    ret     = plaform_init_hardware_impl();
    if (0 != ret) {
        goto exit;
    }
exit:
    return ret;
}

void platform_init_network(const uint8_t *identifier)
{
    platform_init_network_impl(identifier);
}

void platform_success_indicator()
{
    platform_success_indicator_impl();
}

void platform_failure_indicator()
{
    platform_failure_indicator_impl();
}
