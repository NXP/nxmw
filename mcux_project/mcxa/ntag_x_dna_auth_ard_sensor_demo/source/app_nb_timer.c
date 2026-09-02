/*
 *
 * Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "app_nb_timer.h"

/**
 * @brief Global SysTick tick counter.
 *
 * Incremented every millisecond inside SysTick_Handler_APP_CB().

 * Note: Rolls over after approximately 49.7 days of continuous operation.
 * The timer expiry check in app_nb_timer_expired() handles this rollover
 * correctly using unsigned arithmetic, provided the duration does not
 * exceed UINT32_MAX milliseconds.
 */
volatile uint32_t g_systickTicks = 0U;

/**
 * @brief Start a non-blocking timer.
 *
 * Captures the current tick count and stores the desired duration.
 * Must be called before polling with app_nb_timer_expired().
 *
 * @param t           Pointer to the timer instance. Must not be NULL.
 * @param duration_ms Desired timeout duration in milliseconds.
 */
void app_nb_timer_start(app_nb_timer_t *t, uint32_t duration_ms)
{
    t->start    = g_systickTicks;
    t->duration = duration_ms;
}

/**
 * @brief Check whether a non-blocking timer has expired.
 *
 * Uses unsigned subtraction to correctly handle a uint32_t rollover
 * of g_systickTicks (wraps around after ~49.7 days).
 *
 * @param t Pointer to the timer instance. Must not be NULL.
 * @return  Non-zero (true) if elapsed time >= duration, zero (false) otherwise.
 */
int app_nb_timer_expired(app_nb_timer_t *t)
{
    return ((g_systickTicks - t->start) >= t->duration);
}
