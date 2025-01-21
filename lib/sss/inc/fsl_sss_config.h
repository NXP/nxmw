/*
 *
 * Copyright 2018,2019 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FSL_SSS_CONFIG_H_
#define _FSL_SSS_CONFIG_H_

/* clang-format off */
#define SSS_SESSION_MAX_CONTEXT_SIZE        ( 0 \
    + (1 * sizeof(void *)) \
    + (1 * sizeof(void *)) \
    + (12 * sizeof(void *)) \
    + 32)
#define SSS_KEY_STORE_MAX_CONTEXT_SIZE      ( 0 \
    + (1 * sizeof(void *)) \
    + (4 * sizeof(void *)) \
    + 32)
#define SSS_KEY_OBJECT_MAX_CONTEXT_SIZE     ( 0 \
    + (1 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (4 * sizeof(void *)) \
    + 32 + 128)
#define SSS_SYMMETRIC_MAX_CONTEXT_SIZE      ( 0 \
    + (2 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 16 /* Buffer in case of unaligned block cipher operations */ \
    + 4  /* Buffer length in case of unaligned block cipher operations */ \
    + 32)
#define SSS_AEAD_MAX_CONTEXT_SIZE           ( 0 \
    + (5 * sizeof(void *)) \
    + (6 * sizeof(int)) \
    + (5 * sizeof(void *)) \
    + 32)
#define SSS_DIGEST_MAX_CONTEXT_SIZE         ( 0 \
    + (1 * sizeof(void *)) \
    + (3 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 32)
#define SSS_MAC_MAX_CONTEXT_SIZE            ( 0 \
    + (2 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 32)
#define SSS_ASYMMETRIC_MAX_CONTEXT_SIZE      ( 0 \
    + (2 * sizeof(void *)) \
    + (3 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 32)
#define SSS_TUNNEL_MAX_CONTEXT_SIZE         ( 0 \
    + (1 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 32)
#define SSS_CHANNEL_MAX_CONTEXT_SIZE         ( 0 \
    + (2 * sizeof(void *)) \
    + 32)
#define SSS_DERIVE_KEY_MAX_CONTEXT_SIZE     ( 0 \
    + (2 * sizeof(void *)) \
    + (2 * sizeof(int)) \
    + (2 * sizeof(void *)) \
    + 32)
#define SSS_RNG_MAX_CONTEXT_SIZE            ( 0 \
    + (1 * sizeof(void *)) \
    + (2 * sizeof(void *)) \
    + 32)

#define SSS_CONNECT_MAX_CONTEXT_SIZE ( 0 \
    + (4 * sizeof(void *)) \
    + 8 \
    )

#define SSS_AUTH_MAX_CONTEXT_SIZE ( 0 \
    + (3 * sizeof(void *)) \
    + 8 \
    )

#define SSS_POLICY_COUNT_MAX (10)
#define SSS_POLICY_BUF_SIZE 3
#define SSS_TB_POLICY_MAX_COUNT 8
#define SSS_SB_POLICY_MAX_COUNT 16
#define SSS_MAX_KEY_DATA_SIZE 32

/* clang-format on */

#endif /* _FSL_SSS_CONFIG_H_ */
