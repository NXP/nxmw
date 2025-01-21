/*
 *
 * Copyright 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include "ex_sss_boot.h"
#include "nxEnsure.h"
#include "nxLog_msg.h"
#include <string.h>
#include "nx_apdu.h"
#include "nx_enums.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

static ex_sss_boot_ctx_t gex_sss_get_version_boot_ctx;

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_get_version_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 0

#include <ex_sss_main_inc.h>

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_nx_session_t *pSession     = NULL;
    smStatus_t sm_status           = SM_NOT_OK;
    sss_status_t status            = kStatus_SSS_Fail;
    Nx_VersionParams_t versionInfo = {0};
    bool getFabID                  = true;

    ENSURE_OR_GO_CLEANUP(NULL != pCtx)
    pSession = (sss_nx_session_t *)&pCtx->session;

    LOG_I("Running Get Card Version Example ex_sss_get_version.c");

    LOG_I("Get Card Version");

    sm_status = nx_GetVersion(&((sss_nx_session_t *)pSession)->s_ctx, getFabID, &versionInfo);
    ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);

    LOG_I("Successful !!!");

    if (versionInfo.vendorID1 == 0x04) {
        LOG_I("HW Vendor ID: NXP Semiconductors");
    }
    else {
        LOG_I("HW Vendor ID: 0x%x", versionInfo.vendorID1);
    }

    if (versionInfo.hwType == 0x04) {
        LOG_I("HW type: NTAG");
    }
    else if (versionInfo.hwType == 0x0A) {
        LOG_I("HW type: IoT");
    }
    else {
        LOG_I("HW type: 0x%x", versionInfo.hwType);
    }

    if (versionInfo.hwSubType == 0x41) {
        LOG_I("HW subtype: 17 pF, Tag Tamper");
    }
    else if (versionInfo.hwSubType == 0x43) {
        LOG_I("HW subtype: 50 pF, Tag Tamper");
    }
    else {
        LOG_I("HW subtype 0x%x", versionInfo.hwSubType);
    }

    if (versionInfo.hwMajorVersion == 0xA0) {
        LOG_I("HW major version: NX (Zen-V)");
    }
    else {
        LOG_I("HW major version: 0x%x", versionInfo.hwMajorVersion);
    }

    LOG_I("HW minor version 0x%x", versionInfo.hwMinorVersion);

    if (versionInfo.hwStorageSize == 0x1A) {
        LOG_I("HW storage size: 8 kB");
    }
    else if (versionInfo.hwStorageSize == 0x1C) {
        LOG_I("HW storage size: 16 kB");
    }
    else {
        LOG_I("HW storage size: 0x%x", versionInfo.hwStorageSize);
    }

    if (versionInfo.hwProtocol == 0x15) {
        LOG_I("HW protocol type: ISO/IEC 14443-4 support with Silent Mode support");
    }
    else if (versionInfo.hwProtocol == 0x20) {
        LOG_I("HW protocol type: I2C");
    }
    else if (versionInfo.hwProtocol == 0x35) {
        LOG_I("HW protocol type: I2C and ISO/IEC 14443-4 support with Silent Mode support");
    }
    else {
        LOG_I("HW protocol type: 0x%x", versionInfo.hwProtocol);
    }

    if (versionInfo.vendorID2 == 0x04) {
        LOG_I("SW Vendor ID: NXP Semiconductors");
    }
    else {
        LOG_I("SW Vendor ID: 0x%x", versionInfo.vendorID2);
    }

    if (versionInfo.swType == 0x04) {
        LOG_I("SW type: NTAG");
    }
    else if (versionInfo.swType == 0x0A) {
        LOG_I("SW type: IoT");
    }
    else {
        LOG_I("SW type: 0x%x", versionInfo.swType);
    }

    if (versionInfo.swSubType == 0x01) {
        LOG_I("SW subtype: Standalone");
    }
    else {
        LOG_I("SW subtype 0x%x", versionInfo.swSubType);
    }

    if (versionInfo.swMajorVersion == 0x00) {
        LOG_I("SW major version: EV0");
    }
    else {
        LOG_I("SW major version: 0x%x", versionInfo.swMajorVersion);
    }

    LOG_I("SW minor version 0x%x", versionInfo.swMinorVersion);

    if (versionInfo.swStorageSize == 0x1A) {
        LOG_I("SW storage size: 8 kB");
    }
    else if (versionInfo.swStorageSize == 0x1C) {
        LOG_I("SW storage size: 16 kB");
    }
    else {
        LOG_I("SW storage size: 0x%x", versionInfo.swStorageSize);
    }

    if (versionInfo.swProtocol == 0x15) {
        LOG_I("SW protocol type: ISO/IEC 14443-4 support with Silent Mode support");
    }
    else if (versionInfo.swProtocol == 0x20) {
        LOG_I("SW protocol type: I2C");
    }
    else if (versionInfo.swProtocol == 0x35) {
        LOG_I("SW protocol type: I2C and ISO/IEC 14443-4 support with Silent Mode support");
    }
    else {
        LOG_I("SW protocol type: 0x%x", versionInfo.swProtocol);
    }

    if (versionInfo.uidFormat != NX_VERSION_UID_FORMAT_INVALID) {
        LOG_I("UIDFormat: 0x%x", versionInfo.uidFormat);
        LOG_I("UIDLength: 0x%x", versionInfo.uidLength);
    }
    LOG_MAU8_I("Card UID", versionInfo.uid, versionInfo.uidLength);
    LOG_I("BatchNo: 0x%x", versionInfo.batchNo);
    LOG_I("FabKey identifier: 0x%x", versionInfo.fabKeyID);
    LOG_I("Calendar week of card production in BCD coding: 0x%x", versionInfo.cwProd);
    LOG_I("The year of production in BCD coding: 0x%x", versionInfo.yearProd);
    if (getFabID) {
        LOG_I("Fab Identifier: 0x%x", versionInfo.fabID);
    }

cleanup:
    if (SM_OK == sm_status) {
        LOG_I("ex_sss_get_version Example Success !!!...");
        status = kStatus_SSS_Success;
    }
    else {
        LOG_E("ex_sss_get_version Example Failed !!!...");
        status = kStatus_SSS_Fail;
    }

    return status;
}
