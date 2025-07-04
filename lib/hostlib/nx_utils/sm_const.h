/*
*
* Copyright 2022-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef _SM_CONST_H_
#define _SM_CONST_H_

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_NX_TYPE_NX_R_DA
#define APPLET_NAME                              \
    {                                            \
        0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 \
    }
#define APPLET_NAME_LEN (7)

#define SSD_NAME                                                         \
    {                                                                    \
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03 \
    }
#elif SSS_HAVE_NX_TYPE_NX_PICC
#define APPLET_NAME                              \
    {                                            \
        0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00 \
    }
#define APPLET_NAME_LEN (7)

#define SSD_NAME                                                         \
    {                                                                    \
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03 \
    }
#elif SSS_HAVE_NX_TYPE
#define APPLET_NAME                                                                                    \
    {                                                                                                  \
        0xa0, 0x00, 0x00, 0x03, 0x96, 0x54, 0x53, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00 \
    }
#define APPLET_NAME_LEN (16)

#define SSD_NAME                                                         \
    {                                                                    \
        0xD2, 0x76, 0x00, 0x00, 0x85, 0x30, 0x4A, 0x43, 0x4F, 0x90, 0x03 \
    }
#endif

#if SSS_HAVE_NX_TYPE_NX_R_DA || SSS_HAVE_NX_TYPE_NX_PICC
#define SE_NAME "NX_SA"
#endif

#endif //_SM_CONST_H_
