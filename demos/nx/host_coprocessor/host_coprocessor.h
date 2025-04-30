/* Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HOST_COPROCESSOR_H_
#define HOST_COPROCESSOR_H_

#include <stddef.h>
#include "board.h"

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

// frdm64f define i2c channels base address
#if defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F == 1)
#define AX_I2C0M I2C0
#define AX_I2CM I2C1
#elif defined(SSS_HAVE_HOST_FRDMMCXN947) && (SSS_HAVE_HOST_FRDMMCXN947 == 1)
#define AX_I2C0M ((LPI2C_Type *)(LPI2C3_BASE))
#define AX_I2CM ((LPI2C_Type *)(LPI2C2_BASE))
#elif defined(SSS_HAVE_HOST_FRDMMCXA153) && (SSS_HAVE_HOST_FRDMMCXA153)
#define AX_I2C0M LPI2C0
#define AX_I2CM I3C0
#endif

#define CLA_ISO7816 (0x00) //!< ISO7816-4 defined CLA byte

typedef enum
{
    SM_NOT_OK                              = 0xFFFF,
    SM_OK                                  = 0x9000,
    SM_OK_ALT                              = 0x9100,
    SM_ERR_WRONG_LENGTH                    = 0x6700,
    SM_ERR_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985,
    SM_ERR_ACCESS_DENIED_BASED_ON_POLICY   = 0x6986,
    SM_ERR_SECURITY_STATUS                 = 0x6982,
    SM_ERR_WRONG_DATA                      = 0x6A80,
    SM_ERR_DATA_INAVILD                    = 0x6984,
    SM_ERR_FILE_FULL                       = 0x6A84,
    SM_ERR_FILE_PERMISSION_DENIED          = 0x919D,
    SM_ERR_FILE_PARAMETER                  = 0x919E,
    SM_ERR_FILE_AUTH                       = 0x91AE,
    SM_ERR_FILE_BOUNDARY                   = 0x91BE,
    SM_ERR_FILE_NOT_EXIST                  = 0x91F0,
    SM_ERR_FILE_DUPLICATE                  = 0x91DE,
} smStatus_t;

/** Values for P1 in ISO7816 APDU */
typedef enum
{
    /** Default P1 */
    NX_P1_DEFAULT = 0x00,
} NX_P1_t;

/** Values for P2 in ISO7816 APDU */
typedef enum
{
    /** Default P2 */
    NX_P2_DEFAULT = 0x00,
} NX_P2_t;

#define INS_GP_ISO_GENERAL_AUTHENTICATE (0x86) //!< Global platform defined instruction
#define INS_NX_PROCESS_SM (0xE5)
#define NX_CLA (0x90)
#define NX_INS_FREE_MEM (0x6E)
#define P1_SIGMA_I (0x01)
#define P2_SIGMA_I (0x00) // edit this if sigma_I_auth_selected keyID 01

/** Header for a IS716 APDU */
typedef struct
{
    /** ISO 7816 APDU Header */
    uint8_t hdr[0   /* For Indentation */
                + 1 /* CLA */
                + 1 /* INS */
                + 1 /* P1 */
                + 1 /* P2 */
    ];
} tlvHeader_t;

/** ProcessSM Action */
typedef enum
{
    Nx_ProcessSM_Action_Apply  = 0x01,
    Nx_ProcessSM_Action_Remove = 0x02,
} Nx_ProcessSM_Action_t;

/** ProcessSM Operation */
typedef enum
{
    Nx_ProcessSM_Operation_Oneshot = 0x04,
} Nx_ProcessSM_Operation_t;

/** Communication Modes */
typedef enum
{
    Nx_CommMode_Plain = 0x00,
    Nx_CommMode_MAC   = 0x01,
    Nx_CommMode_FULL  = 0x03,
    Nx_CommMode_NA    = 0x7F,
} Nx_CommMode_t;

#define NX_PROCESSSM_PLAIN_TEXT_LENGTH_MAX 240
#define NX_PROCESSSM_PLAIN_TEXT_LENGTH_MIN 1
#endif // HOST_COPROCESSOR_H_