/*
 *
 * Copyright 2018-2020, 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Common Key store implementation between keystore_a7x and keystore_pc */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "fsl_sss_keyid_map.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"

/* ************************************************************************** */
/* Local Defines                                                              */
/* ************************************************************************** */

/* ************************************************************************** */
/* Structures and Typedefs                                                    */
/* ************************************************************************** */

/* ************************************************************************** */
/* Global Variables                                                           */
/* ************************************************************************** */

/* ************************************************************************** */
/* Static function declarations                                               */
/* ************************************************************************** */

/* ************************************************************************** */
/* Public Functions                                                           */
/* ************************************************************************** */

void ks_common_init_fat(keyStoreTable_t *keystore_shadow, keyIdAndTypeIndexLookup_t *lookup_entires, size_t max_entries)
{
    ENSURE_OR_GO_EXIT(NULL != keystore_shadow)
    ENSURE_OR_GO_EXIT(NULL != lookup_entires)

    memset(keystore_shadow, 0, sizeof(*keystore_shadow));
    keystore_shadow->magic   = KEYSTORE_MAGIC;
    keystore_shadow->version = KEYSTORE_VERSION;
    if (max_entries > UINT16_MAX) {
        LOG_E("max_entries Cannot be greater than 0xffff");
        goto exit;
    }
    keystore_shadow->maxEntries = (uint16_t)max_entries;
    keystore_shadow->entries    = lookup_entires;
    memset(keystore_shadow->entries, 0, sizeof(*lookup_entires) * max_entries);

exit:
    return;
}

sss_status_t ks_common_update_fat(keyStoreTable_t *keystore_shadow,
    uint32_t extId,
    sss_key_part_t key_part,
    sss_cipher_type_t cipherType,
    uint8_t intIndex,
    uint32_t accessPermission,
    uint16_t keyLen)
{
    sss_status_t retval      = kStatus_SSS_Fail;
    uint32_t i               = 0;
    bool found_entry         = FALSE;
    uint8_t slots_req        = 1;
    uint8_t entries_written  = 0;
    uint16_t keyLen_roundoff = 0;

    ENSURE_OR_GO_CLEANUP(NULL != keystore_shadow)

    retval = isValidKeyStoreShadow(keystore_shadow);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == retval)

    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        ENSURE_OR_GO_CLEANUP(NULL != keyEntry)

        if (keyEntry->extKeyId == extId) {
            LOG_W("ENTRY already exists 0x%04X", extId);
            retval      = kStatus_SSS_Fail;
            found_entry = TRUE;
            break;
        }
    }

    if (key_part == kSSS_KeyPart_Default && (cipherType == kSSS_CipherType_AES || cipherType == kSSS_CipherType_HMAC)) {
        if ((keyLen > (UINT16_MAX - 16)) || (keyLen == 0)) {
            retval = kStatus_SSS_Fail;
            goto cleanup;
        }
        keyLen_roundoff = ((keyLen / 16u) * 16u) + ((keyLen % 16u) == 0 ? 0 : 16u);
        slots_req       = (keyLen_roundoff / 16u);
    }

    if (FALSE == found_entry) {
        retval = kStatus_SSS_Fail;
        for (i = 0; i < keystore_shadow->maxEntries; i++) {
            keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
            if (keyEntry->extKeyId == 0) {
                keyEntry->extKeyId    = extId;
                keyEntry->keyIntIndex = intIndex;
                if ((key_part | ((slots_req - 1) << 4)) > UINT8_MAX) {
                    retval = kStatus_SSS_Fail;
                    goto cleanup;
                }
                keyEntry->keyPart    = key_part | ((slots_req - 1) << 4);
                keyEntry->cipherType = cipherType;

                entries_written++;
                if (entries_written == slots_req) {
                    retval = kStatus_SSS_Success;
                    break;
                }
            }
        }
    }
cleanup:
    return retval;
}

sss_status_t ks_common_remove_fat(keyStoreTable_t *keystore_shadow, uint32_t extId)
{
    sss_status_t retval = kStatus_SSS_Fail;
    uint32_t i          = 0;
    bool found_entry    = FALSE;

    ENSURE_OR_GO_CLEANUP(NULL != keystore_shadow)

    retval = isValidKeyStoreShadow(keystore_shadow);
    ENSURE_OR_GO_CLEANUP(kStatus_SSS_Success == retval)

    for (i = 0; i < keystore_shadow->maxEntries; i++) {
        keyIdAndTypeIndexLookup_t *keyEntry = &keystore_shadow->entries[i];
        ENSURE_OR_GO_CLEANUP(NULL != keyEntry)

        if (keyEntry->extKeyId == extId) {
            retval = kStatus_SSS_Success;
            memset(keyEntry, 0, sizeof(keyIdAndTypeIndexLookup_t));
            found_entry = TRUE;
        }
    }
    if (TRUE != found_entry) {
        retval = kStatus_SSS_Fail;
    }
cleanup:
    return retval;
}

/* ************************************************************************** */
/* Private Functions                                                          */
/* ************************************************************************** */

sss_status_t isValidKeyStoreShadow(keyStoreTable_t *keystore_shadow)
{
    sss_status_t retval = kStatus_SSS_Fail;

    ENSURE_OR_GO_CLEANUP(NULL != keystore_shadow)

    if (keystore_shadow->magic != KEYSTORE_MAGIC) {
        LOG_E("Mismatch.keystore_shadow->magic and KEYSTORE_MAGIC");
        goto cleanup;
    }
    if (keystore_shadow->version != KEYSTORE_VERSION) {
        LOG_E(" Version mismatch.");
        goto cleanup;
    }
    if (keystore_shadow->maxEntries == 0) {
        LOG_E("Keystore not yet allocated");
        goto cleanup;
    }
    retval = kStatus_SSS_Success;

cleanup:
    return retval;
}
