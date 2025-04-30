/*
 *  PSA ITS simulator over stdio files.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  Copyright 2020 NXP
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "psa_crypto_its.h"
#include "psa_crypto_storage.h"

psa_status_t psa_its_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info);

psa_status_t psa_its_get(
    psa_storage_uid_t uid, uint32_t data_offset, uint32_t data_length, void *p_data, size_t *p_data_length);

psa_status_t psa_its_set(
    psa_storage_uid_t uid, uint32_t data_length, const void *p_data, psa_storage_create_flags_t create_flags);

psa_status_t psa_its_remove(psa_storage_uid_t uid);
