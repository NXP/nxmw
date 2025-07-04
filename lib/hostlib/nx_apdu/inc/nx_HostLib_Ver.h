/* Copyright 2019-2021 NXP
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 * 
 */

#ifndef NX_HOSTLIB_VERSION_INFO_H_INCLUDED
#define NX_HOSTLIB_VERSION_INFO_H_INCLUDED

/* clang-format off */
#define NX_HOSTLIB_PROD_NAME          "NX_HostLib"
#define NX_HOSTLIB_VER_STRING_NUM     "v02.05.01_20250515"
#define NX_HOSTLIB_PROD_NAME_VER_FULL "NX_HostLib_v02.05.01_20250515"
#define NX_HOSTLIB_VER_MAJOR          (2u)
#define NX_HOSTLIB_VER_MINOR          (5u)
#define NX_HOSTLIB_VER_DEV            (1u)

/* v02.05 = 20005u */
#define NX_HOSTLIB_VER_MAJOR_MINOR ( 0 \
    | (NX_HOSTLIB_VER_MAJOR * 10000u)    \
    | (NX_HOSTLIB_VER_MINOR))

/* v02.05.00 = 200050000ULL */
#define NX_HOSTLIB_VER_MAJOR_MINOR_DEV ( 0 \
    | (NX_HOSTLIB_VER_MAJOR * 10000*10000u)    \
    | (NX_HOSTLIB_VER_MINOR * 10000u)    \
    | (NX_HOSTLIB_VER_DEV))

/* clang-format on */

#endif /* NX_HOSTLIB_VERSION_INFO_H_INCLUDED */
