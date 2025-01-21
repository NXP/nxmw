/*
 *
 * Copyright 2017-2020, 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 *
 * I2C API used by T=1 over I2C protocol implementation.
 *
 * - T=1 over I2C is the protocol used by NX family of Secure Authenticators.
 *
 * - T=1 over I2C with GP is the protocol used by other Secure Authenticators.
 *
 * These APIs are to be implemented when porting the Middleware stack to a new
 * host platform.
 *
 * # Convention of the APIs.
 *
 *
 * APIs for which a buffer is input. e.g.::
 *
 *   i2c_error_t axI2CWrite(unsigned char bus, unsigned char addr,
 *   unsigned char * pTx, unsigned short txLen);
 *
 *
 * In the above case :samp:`pTx` is a buffer input.  It is assumed that
 * the lengh as set in :samp:`txLen` is same as that pointed to by
 * :samp:`pTx`.  This parameter is used as is and any mistake by the
 * calling/implemented API will have unpredictable errors.
 *
 *
 * APIs for which a buffer is output. e.g.::
 *
 * i2c_error_t axI2CWriteRead(unsigned char bus,
 *     unsigned char addr,
 *     unsigned char *pTx,
 *     unsigned short txLen,
 *     unsigned char *pRx,
 *     unsigned short *pRxLen);
 *
 *
 * In the above case :samp:`pRx` is a buffer output and :samp:`pRxLen`
 * is both input and output. It is assumed that the lengh as set in
 * :samp:`pRxLen` is set to the maximum as available to the pointer
 * pointed by :samp:`pRx`.  This parameter is used as is and any mistake
 * by the calling/implemented API will have unpredictable errors.
 *
 * @par History
 *
 **/

#ifndef _I2C_A7_H
#define _I2C_A7_H

#include "sm_types.h"
#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#define SCI2C_T_CMDG 180 //!< Minimum delay between stop of Wakeup command and start of subsequent command (Value in micro seconds)

#define I2C_IDLE              0
#define I2C_STARTED           1
#define I2C_RESTARTED         2
#define I2C_REPEATED_START    3
#define DATA_ACK              4
#define DATA_NACK             5
#define I2C_BUSY              6
#define I2C_NO_DATA           7
#define I2C_NACK_ON_ADDRESS   8
#define I2C_NACK_ON_DATA      9
#define I2C_ARBITRATION_LOST  10
#define I2C_TIME_OUT          11
#define I2C_OK                12
#define I2C_FAILED            13

typedef unsigned int i2c_error_t;
#define I2C_BUS_0   (0)

#if defined(__cplusplus)
extern "C"{
#endif
/** Initialize the I2C platform HW/Driver*/

/* MAX data supported by respective protocol in single read/write*/
#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0)
#define MAX_DATA_LEN      260
#endif


i2c_error_t axI2CInit(void **conn_ctx, const char *pDevName);

/** Terminate / de-initialize the I2C platform HW/Driver
 *
 *
 * @param[in] connection context.
 * @param[in] mode Can be either 0 or 1.
 *
 *            Where applicable, and implemented a value of 0 corresponds
 *            to a 'light-weight' terminate.
 *
 *            In genral, this is not used for most of the porting
 *            platforms and use cases.
 *
 *
 */
void axI2CTerm(void* conn_ctx, int mode);

#if defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)
/** Smarter handling of back off logic
 *
 *  When we get a NAK from SE, we back off and keep on increasing the delay for next I2C Read/Write.
 *
 *  When we get an ACK from SE, we reset this back off delay.
 */
void axI2CResetBackoffDelay( void );
#endif /* SSS_HAVE_HOST_FRDMK64F */

#if defined(SSS_HAVE_SMCOM_T1OI2C_GP1_0)
/** Write a frame.
 *
 * Needed for SCI2C and T=1 over I2C */
i2c_error_t axI2CWrite(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pTx, unsigned short txLen);

/** Read a byte.
 *
 * Needed only for T=1 over I2C */
i2c_error_t axI2CRead(void* conn_ctx, unsigned char bus, unsigned char addr, unsigned char * pRx, unsigned short rxLen);
#endif /* SSS_HAVE_SMCOM_T1OI2C_GP1_0 */
#if defined(__cplusplus)
}
#endif

#endif // _I2C_A7_H
