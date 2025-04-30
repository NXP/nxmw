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
        LOG_I("HW Vendor ID: 0x%02X (NXP Semiconductors)", versionInfo.vendorID1);
    }
    else {
        LOG_I("HW Vendor ID: 0x%02X", versionInfo.vendorID1);
    }

    if (versionInfo.hwType == 0x04) {
        LOG_I("HW type: 0x%02X (NTAG)", versionInfo.hwType);
    }
    else if (versionInfo.hwType == 0x0A) {
        LOG_I("HW type: 0x%02X (IoT)", versionInfo.hwType);
    }
    else {
        LOG_I("HW type: 0x%02X", versionInfo.hwType);
    }

    if (versionInfo.hwSubType == 0x41) {
        LOG_I("HW subtype: 0x%02X (17 pF, Tag Tamper)", versionInfo.hwSubType);
    }
    else if (versionInfo.hwSubType == 0x43) {
        LOG_I("HW subtype: 0x%02X (50 pF, Tag Tamper)", versionInfo.hwSubType);
    }
    else {
        LOG_I("HW subtype: 0x%02X", versionInfo.hwSubType);
    }

    LOG_I("HW major version: 0x%02X", versionInfo.hwMajorVersion);

    LOG_I("HW minor version: 0x%02X", versionInfo.hwMinorVersion);

    if (versionInfo.hwStorageSize == 0x1A) {
        LOG_I("HW storage size: 0x%02X (8 kB)", versionInfo.hwStorageSize);
    }
    else if (versionInfo.hwStorageSize == 0x1C) {
        LOG_I("HW storage size: 0x%02X (16 kB)", versionInfo.hwStorageSize);
    }
    else {
        LOG_I("HW storage size: 0x%02X", versionInfo.hwStorageSize);
    }

    if (versionInfo.hwProtocol == 0x15) {
        LOG_I("HW protocol type: 0x%02X (ISO/IEC 14443-4 support with Silent Mode support)", versionInfo.hwProtocol);
    }
    else if (versionInfo.hwProtocol == 0x20) {
        LOG_I("HW protocol type: 0x%02X (I2C)", versionInfo.hwProtocol);
    }
    else if (versionInfo.hwProtocol == 0x35) {
        LOG_I("HW protocol type: 0x%02X (I2C and ISO/IEC 14443-4 support with Silent Mode support)",
            versionInfo.hwProtocol);
    }
    else {
        LOG_I("HW protocol type: 0x%02X", versionInfo.hwProtocol);
    }

    if (versionInfo.vendorID2 == 0x04) {
        LOG_I("SW Vendor ID: 0x%02X (NXP Semiconductors)", versionInfo.vendorID2);
    }
    else {
        LOG_I("SW Vendor ID: 0x%02X", versionInfo.vendorID2);
    }

    if (versionInfo.swType == 0x04) {
        LOG_I("SW type: 0x%02X (NTAG X DNA)", versionInfo.swType);
    }
    else if (versionInfo.swType == 0x0A) {
        LOG_I("SW type: 0x%02X (A30)", versionInfo.swType);
    }
    else {
        LOG_I("SW type: 0x%02X", versionInfo.swType);
    }

    if (versionInfo.swSubType == 0x01) {
        LOG_I("SW subtype: 0x%02X (Standalone)", versionInfo.swSubType);
    }
    else {
        LOG_I("SW subtype: 0x%02X", versionInfo.swSubType);
    }

    LOG_I("SW major version: 0x%02X", versionInfo.swMajorVersion);

    LOG_I("SW minor version: 0x%02X", versionInfo.swMinorVersion);

    if (versionInfo.swStorageSize == 0x1A) {
        LOG_I("SW storage size: 0x%02X (8 kB)", versionInfo.swStorageSize);
    }
    else if (versionInfo.swStorageSize == 0x1C) {
        LOG_I("SW storage size: 0x%02X (16 kB)", versionInfo.swStorageSize);
    }
    else {
        LOG_I("SW storage size: 0x%02X", versionInfo.swStorageSize);
    }

    if (versionInfo.swProtocol == 0x15) {
        LOG_I("SW protocol type: 0x%02X (ISO/IEC 14443-4 support with Silent Mode support)", versionInfo.swProtocol);
    }
    else if (versionInfo.swProtocol == 0x20) {
        LOG_I("SW protocol type: 0x%02X (I2C)", versionInfo.swProtocol);
    }
    else if (versionInfo.swProtocol == 0x35) {
        LOG_I("SW protocol type: 0x%02X (I2C and ISO/IEC 14443-4 support with Silent Mode support)",
            versionInfo.swProtocol);
    }
    else {
        LOG_I("SW protocol type: 0x%02X", versionInfo.swProtocol);
    }

    if (versionInfo.uidFormat != NX_VERSION_UID_FORMAT_INVALID) {
        LOG_I("UIDFormat: 0x%02X", versionInfo.uidFormat);
        LOG_I("UIDLength: 0x%02X", versionInfo.uidLength);
    }
    LOG_MAU8_I("Card UID", versionInfo.uid, versionInfo.uidLength);
    LOG_I("BatchNo: 0x%06X", versionInfo.batchNo);
    LOG_I("FabKey identifier: 0x%04X", versionInfo.fabKeyID);
    LOG_I("Calendar week of card production in BCD coding: 0x%02X", versionInfo.cwProd);
    LOG_I("The year of production in BCD coding: 0x%02X", versionInfo.yearProd);
    if (getFabID) {
        LOG_I("Fab Identifier: 0x%02X", versionInfo.fabID);
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
