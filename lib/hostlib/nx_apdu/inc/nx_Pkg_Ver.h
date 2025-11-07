/* Copyright 2019-2021, 2025 NXP
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 * 
 */

#ifndef NX_PKG_VERSION_INFO_H_INCLUDED
#define NX_PKG_VERSION_INFO_H_INCLUDED

/* clang-format off */
#define NX_PKG_PROD_NAME          "NX_PKG"
#define NX_PKG_VER_STRING_NUM     "v02.07.00_20251107"
#define NX_PKG_PROD_NAME_VER_FULL "NX_PKG_v02.07.00_20251107"
#define NX_PKG_VER_MAJOR          (2u)
#define NX_PKG_VER_MINOR          (7u)
#define NX_PKG_VER_DEV            (0u)

/* v02.07 = 20007u */
#define NX_PKG_VER_MAJOR_MINOR ( 0 \
    | (NX_PKG_VER_MAJOR * 10000u)    \
    | (NX_PKG_VER_MINOR))

/* v02.07.00 = 200070000ULL */
#define NX_PKG_VER_MAJOR_MINOR_DEV ( 0 \
    | (NX_PKG_VER_MAJOR * 10000*10000u)    \
    | (NX_PKG_VER_MINOR * 10000u)    \
    | (NX_PKG_VER_DEV))

/* clang-format on */

#endif /* NX_PKG_VERSION_INFO_H_INCLUDED */
