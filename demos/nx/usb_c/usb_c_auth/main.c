/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "usb_c_auth.h"

ex_sss_boot_ctx_t gex_usb_c_auth_ctx;
sss_session_t *pgSssSession     = &(gex_usb_c_auth_ctx.session);
sss_key_store_t *pgKeyStore     = &(gex_usb_c_auth_ctx.ks);
sss_session_t *pghostSession    = &(gex_usb_c_auth_ctx.host_session);
sss_key_store_t *pghostKeyStore = &(gex_usb_c_auth_ctx.host_ks);

#define EX_SSS_BOOT_PCONTEXT (&gex_usb_c_auth_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>
