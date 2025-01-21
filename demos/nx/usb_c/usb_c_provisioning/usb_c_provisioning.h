/* Copyright 2023 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __USB_C_PROVISIONING_H_
#define __USB_C_PROVISIONING_H_

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */

#include "ex_sss_boot.h"
#include "usb_c_common.h"

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

/* doc:start:usb_c-slot-id */
/* Update the SLOT_ID to provision for another slot
 * Valid values are 0, 1, 2, 3
 */
#define USB_C_PROVISIONING_SLOT_ID 0
/* doc:end:usb_c-slot-id */

extern const uint8_t usb_c_ec_priv_key[];
extern const uint8_t usb_c_certificate_chain[];
extern const uint8_t usb_c_certificate_chain_hash[];
extern const size_t usb_c_ec_priv_key_len;
extern const size_t usb_c_certificate_chain_len;
extern const size_t usb_c_certificate_chain_hash_len;

#endif /* __USB_C_PROVISIONING_H_ */
