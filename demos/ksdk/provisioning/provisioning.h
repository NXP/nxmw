/* Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef DEMOS_KSDK_PROVISIONING_PROVISIONING_H_
#define DEMOS_KSDK_PROVISIONING_PROVISIONING_H_

#include <ex_sss_boot.h>
#include <fsl_sss_api.h>
#include "fsl_sss_nx_apis.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include <nx_apdu.h>
#include <nx_enums.h>
#include <fsl_sss_util_asn1_der.h>

int ex_util_asn1_get_ec_pair_key_index(const uint8_t *input,
    size_t inLen,
    uint8_t *pubkeyIndex,
    size_t *publicKeyLen,
    uint8_t *prvkeyIndex,
    size_t *privateKeyLen);

#endif /* DEMOS_KSDK_PROVISIONING_PROVISIONING_H_ */
