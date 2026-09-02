/*
 *
 * Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef APP_NB_TIMER_H_
#define APP_NB_TIMER_H_

#include <stdint.h>

/**
 * @brief Global SysTick counter incremented every millisecond by SysTick_Handler_APP_CB.
 * Declared volatile to prevent compiler optimization since it is modified in an ISR.
 */
extern volatile uint32_t g_systickTicks;

/**
 * @brief Non-blocking timer structure.
 *
 * Stores the start tick and duration to allow non-blocking timeout checks.
 * Use app_nb_timer_start() to initialize and app_nb_timer_expired() to poll.
 */
typedef struct
{
    uint32_t start;    /**< Tick value captured when the timer was started. */
    uint32_t duration; /**< Timer duration in milliseconds. */
} app_nb_timer_t;

/**
 * @brief Start a non-blocking timer.
 *
 * @param t           Pointer to the timer instance to initialize.
 * @param duration_ms Desired timeout duration in milliseconds.
 */
void app_nb_timer_start(app_nb_timer_t *t, uint32_t duration_ms);

/**
 * @brief Check whether a non-blocking timer has expired.
 *
 * This function is safe against a single uint32_t rollover of g_systickTicks
 * because it uses unsigned subtraction.
 *
 * @param t Pointer to the timer instance to check.
 * @return  Non-zero (true) if the timer has expired, zero (false) otherwise.
 */
int app_nb_timer_expired(app_nb_timer_t *t);

#endif /* APP_NB_TIMER_H_ */
