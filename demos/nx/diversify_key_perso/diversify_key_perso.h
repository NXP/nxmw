/*
*
* Copyright 2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#include <fsl_sss_nx_auth_keys.h>

#ifdef EX_SSS_APPKEY_FILE_PATH
sss_status_t nx_util_get_app_keys_from_fs(uint8_t *appkeyBuf, size_t appkeyBufLen, size_t *appkeyLen);
#endif // EX_SSS_APPKEY_FILE_PATH
#ifdef EX_SSS_D_KEY_INPUT_FILE_PATH
sss_status_t ex_sss_util_get_dkeyinput_from_fs(uint8_t *uid,
    size_t uidLen,
    uint8_t *application_identifier,
    size_t application_identifier_len,
    uint8_t *system_identifier,
    size_t system_identifier_len);
#endif // EX_SSS_D_KEY_INPUT_FILE_PATH
