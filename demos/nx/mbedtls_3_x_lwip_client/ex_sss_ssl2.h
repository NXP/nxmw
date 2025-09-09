/* 
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SSS_SSL2__
#define __EX_SSS_SSL2__

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Key type */
#ifndef ECC_KEY_TYPE
#define ECC_KEY_TYPE 1
#endif // ECC_KEY_TYPE

#ifndef DISABLE_EXTENDED_MASTER_SECRET
#define DISABLE_EXTENDED_MASTER_SECRET 0
#endif // DISABLE_EXTENDED_MASTER_SECRET

#define WITH_SA 0

#include "ecc_keys.h"

char gex_sss_argv[13][64] = {
    "none",
    "server_addr=192.168.0.132",
    "server_name=localhost",
    "exchanges=1",
    "force_version=tls12",
    "debug_level=0",
    "ca_file=loadfromfile",
    "auth_mode=required",
#if WITH_SA
    "key_file=none",
    "crt_file=none",
#else
    "key_file=loadfromfile",
    "crt_file=loadfromfile",
#endif
#if ECC_KEY_TYPE
    "force_ciphersuite=TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA",
#endif
#if DISABLE_EXTENDED_MASTER_SECRET
    "extended_ms=0",
#endif
};

#if DISABLE_EXTENDED_MASTER_SECRET

#if ECC_KEY_TYPE
int gex_sss_argc = 12;
#endif

#else

#if ECC_KEY_TYPE
int gex_sss_argc = 11;
#endif
#endif //DISABLE_EXTENDED_MASTER_SECRET
#endif //__EX_SSS_SSL2__