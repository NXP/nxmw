/* Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HOST_COPRO_NX_APDU_H_
#define HOST_COPRO_NX_APDU_H_

#include "host_coprocessor.h"
#include "phNxpEseProto7816_3.h"

smStatus_t nx_ProcessSM_Remove(void **conn_ctx,
    Nx_CommMode_t commMode,
    uint8_t *cipherData,
    size_t cipherDataLen,
    uint8_t *plainData,
    size_t *plainDataLen);

smStatus_t nx_Freemem(void **conn_ctx,
    void **conn2_ctx,
    phNxpEseProto7816_t *pi2c_ps1_ctx,
    phNxpEseProto7816_t *pi2c_ps2_ctx,
    uint32_t *freeMemSize);

smStatus_t nx_ProcessSMApply(void **conn_ctx,
    Nx_CommMode_t commMode,
    uint8_t offset,
    uint8_t cmdCtrIncr,
    uint8_t *plainData,
    size_t plainDataLen,
    uint8_t *cipherData,
    size_t *cipherDataLen);

smStatus_t nx_hcpEstablishSession(void **conn_ctx,
    void **conn2_ctx,
    phNxpEseProto7816_t *pi2c_ps1_ctx,
    phNxpEseProto7816_t *pi2c_ps2_ctx,
    uint8_t *cmdData,
    size_t cmdLen,
    uint8_t *rspData,
    size_t *rspLen);
#endif //HOST_COPRO_NX_APDU_H_