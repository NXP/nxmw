/* Copyright 2019-2021 NXP
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 * 
 * 
 */

#ifndef SSS_APIS_VERSION_INFO_H_INCLUDED
#define SSS_APIS_VERSION_INFO_H_INCLUDED

/* clang-format off */
#define SSS_APIS_PROD_NAME          "SSS_APIs"
#define SSS_APIS_VER_STRING_NUM     "v02.05.00_20250411"
#define SSS_APIS_PROD_NAME_VER_FULL "SSS_APIs_v02.05.00_20250411"
#define SSS_APIS_VER_MAJOR          (2u)
#define SSS_APIS_VER_MINOR          (5u)
#define SSS_APIS_VER_DEV            (0u)

/* v02.05 = 20005u */
#define SSS_APIS_VER_MAJOR_MINOR ( 0 \
    | (SSS_APIS_VER_MAJOR * 10000u)    \
    | (SSS_APIS_VER_MINOR))

/* v02.05.00 = 200050000ULL */
#define SSS_APIS_VER_MAJOR_MINOR_DEV ( 0 \
    | (SSS_APIS_VER_MAJOR * 10000*10000u)    \
    | (SSS_APIS_VER_MINOR * 10000u)    \
    | (SSS_APIS_VER_DEV))

/* clang-format on */

#endif /* SSS_APIS_VERSION_INFO_H_INCLUDED */
