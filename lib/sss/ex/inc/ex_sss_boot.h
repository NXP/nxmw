/*
 *
 * Copyright 2019-2020, 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * ex_sss_boot.h:  *The purpose and scope of this file*
 *
 * Project:
 *
 * $Date:
 * $Author:
 * $Revision$
 */

#ifndef SSS_EX_INC_EX_SSS_BOOT_H_
#define SSS_EX_INC_EX_SSS_BOOT_H_

/* *****************************************************************************************************************
 *   Includes
 * ***************************************************************************************************************** */

#ifdef __cplusplus
extern "C" {
#endif

#include "fsl_sss_api.h"

#if SSS_HAVE_NX_TYPE
#include "fsl_sss_nx_types.h"
#endif

#include "ex_sss_ports.h"
#include "nx_secure_msg_types.h"

/* *****************************************************************************************************************
 * MACROS/Defines
 * ***************************************************************************************************************** */

#define NX_MAX_HOST_KEYPAIR_BUFFER_SIZE 200

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * ***************************************************************************************************************** */
typedef struct
{
    sss_session_t session;
    sss_key_store_t ks;

#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_session_t host_session;
    sss_key_store_t host_ks;
#endif

#if SSS_HAVE_NX_TYPE
    nx_connect_ctx_t nx_open_ctx;
#endif
} ex_sss_boot_ctx_t;

typedef struct
{
    sss_object_t pub_obj;
    sss_object_t obj;
    sss_object_t dev_cert;
    sss_object_t interCaCert;
    sss_key_store_t *pHost_ks;
    uint32_t client_keyPair_index;
    uint32_t client_cert_index;
} ex_sss_cloud_ctx_t;

/* *****************************************************************************************************************
 *   Extern Variables
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 *   Function Prototypes
 * ***************************************************************************************************************** */

/** The case where we connect to the cyrptogrpahic system in-directly.
 *
 * This function is a similar to @ref ex_sss_boot_direct.
 *
 * This function expects that the last argument in argv is the
 * expected/probable port name.
 *
 * e.g. when running form PC, where we are connected
 * to Secure Authenticator via a COM Port/Socket Port.  In such cases,
 * taking the Port number from a Command Line Argument,
 * or Environment Variable would make sense and examples
 * would become more portable.
 *
 * @param argc count of parameters, as received by main
 * @param argv Array of argv, as received by main
 * @param[out] pPortName Possible port name
 * @return 0 if successful.
 */
sss_status_t ex_sss_boot_connectstring(int argc, const char *argv[], char **pPortName);

/**
 * For the case where few activities have to be performed
 * after RTOS initialization, this API would be executed
 * as an RTOS Task.
 *
 * @return
 */
sss_status_t ex_sss_boot_rtos(void *);

/** Is this a serail port */
bool ex_sss_boot_isSerialPortName(const char *portName);

/** Is this --help request */
bool ex_sss_boot_isHelp(const char *argname);

/** Is this a socket port */
bool ex_sss_boot_isSocketPortName(const char *portName);

/** Open an example session */
sss_status_t ex_sss_boot_open(ex_sss_boot_ctx_t *pCtx, const char *portName);

/** Open an example cc session */
sss_status_t ex_sss_boot_open_on_id(ex_sss_boot_ctx_t *pCtx, const char *portName, const int32_t authId);

/** Close an example session */
void ex_sss_session_close(ex_sss_boot_ctx_t *pCtx);

/** Entry Point for each example */
sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx);

#define ex_sss_kestore_and_object_init ex_sss_key_store_and_object_init

sss_status_t ex_sss_key_store_and_object_init(ex_sss_boot_ctx_t *pCtx);

int ex_sss_boot_rtos_init(void);

#if SSS_HAVE_HOSTCRYPTO_ANY
sss_status_t ex_sss_boot_open_host_session(ex_sss_boot_ctx_t *pCtx);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSS_EX_INC_EX_SSS_BOOT_H_ */
