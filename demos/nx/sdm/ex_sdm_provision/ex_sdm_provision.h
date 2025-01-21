/* Copyright 2023-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __EX_SDM_PROVISION_H_
#define __EX_SDM_PROVISION_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "ex_sss_boot.h"
#include "ex_sdm_common.h"

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define EX_SSS_SDM_VCUIDOffset 0x10
#define EX_SSS_SDM_SDMREADCTROffset 0x40
/* clang-format off */
#define EX_SSS_SDM_OLD_AES_KEY                                                                          \
    {                                                                                                   \
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
    }
#define EX_SSS_SDM_ECC_PRIVATE_KEY                                                                      \
    {                                                                                                   \
        0x10, 0xBB, 0xAC, 0x09, 0xBB, 0x49, 0x43, 0x2D, 0xCC, 0x04, 0x79, 0x21, 0xC1, 0x38, 0x0B, 0x78, \
        0xC5, 0x3D, 0x08, 0xCF, 0xAA, 0x1D, 0x59, 0xA0, 0x38, 0x5C, 0x9E, 0x17, 0xF1, 0xBF, 0x92, 0x41, \
    }
/* clang-format on */
#define EX_SSS_SDM_AES_KEY_ID Nx_SDMMetaRead_AccessCondition_Key_0x1
#define EX_SSS_SDM_NEW_AES_KEY_VERSION 1

#define EX_SSS_SDM_ECC_KEY_ID Nx_SDMFileRead_AccessCondition_Key_0x2

#endif /* __EX_SDM_PROVISION_H_ */
