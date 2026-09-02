/*
 * Copyright 2026 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "sm_timer.h"
#include "app_nb_timer.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

/**
 * @brief Application SysTick callback invoked every millisecond.
 *
 * This function is expected to be called from the SysTick interrupt handler
 * once per millisecond.
 * It increments the global tick counter used by the non-blocking timer module.
 *
 * Note: No overflow protection is applied here. g_systickTicks will naturally
 * wrap around after ~49.7 days. The non-blocking timer expiry check handles
 * this rollover correctly via unsigned arithmetic.
 */
void SysTick_Handler_APP_CB(void)
{
	g_systickTicks++;
}
