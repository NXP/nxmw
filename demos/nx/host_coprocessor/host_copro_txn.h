/* Copyright 2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef HOST_COPRO_TXN_H_
#define HOST_COPRO_TXN_H_

#include "host_coprocessor.h"
#include "phEseTypes.h"

#define INS_GP_SELECT (0xA4) //!< Global platform defined instruction
#define P2_NO_FCI (0x0C)     //!< Global platform defined instruction
#define APPLET_NAME                              \
    {                                            \
        0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01 \
    }
#define APPLET_NAME_LEN (7)

smStatus_t nx_hcpTXn(void **conn_ctx,
    const tlvHeader_t *hdr,
    uint8_t *cmdHeader,
    size_t cmdHeaderLen,
    uint8_t *cmdData,
    size_t cmdDataLen,
    uint8_t *rsp,
    size_t *rspLen,
    uint8_t hasle,
    uint8_t isExtended);

smStatus_t hcpContextSwitching(phNxpEseProto7816_t *deinitconn_ctx, phNxpEseProto7816_t *initconn_ctx);

ESESTATUS nx_hcpSelectApplication(void **conn_ctx, const char *pdeviceName);

#endif //HOST_COPRO_TXN_H_