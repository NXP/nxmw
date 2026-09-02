/*
 *
 * Copyright 2026 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @file app_auth_device.h
 * @brief Authentication session management for NX authenticator device.
 *
 * This header provides function declarations for opening and closing
 * authentication sessions using different security methods:
 * - Plain (no authentication)
 * - Symmetric key mutual authentication (AES-128/256)
 * - SIGMA-I (asymmetric) PKI-based based mutual authentication
 *
 * @note Only one session should be active at a time.
 */

#ifndef APP_AUTH_DEVICE_H_
#define APP_AUTH_DEVICE_H_

#include "fsl_sss_api.h"
#include "fsl_sss_nx_types.h"
#include "fsl_sss_ftr.h"
#include "app_auth_ard.h"
/**
 * @brief Reset the authenticator device by power cycling.
 *
 * Powers off the authenticator device, waits for 5ms, then powers it back on.
 * This is typically used for error recovery.
 */
void nx_auth_power_reset(void);

/**
 * @brief Open a plain session with the authenticator device.
 *
 * Establishes a session without any authentication.
 *
 * @param[out] pSession                Double pointer to the session object to be initialized.
 *                                     Must not be NULL. On success, points to the active session.
 * @param[in]  skip_select_application If set to 1, the NDEF Application will not be selected
 *                                     during session open. This is required when opening a session
 *                                     via the I2C interface when using the NFC Pause feature.
 *
 * @return kStatus_SSS_Success on success, error code otherwise.
 *
 * @note Call nx_auth_plain_session_close() to release resources when done.
 */
sss_status_t nx_auth_plain_session_open(sss_nx_session_t **pSession, uint8_t skip_select_application);

/**
 * @brief Close a plain ( session with the authenticator device.
 *
 * Releases resources associated with the plain session.
 * Safe to call with NULL pointer.
 *
 * @param[in] pSession  Pointer to the session object to be closed.
 *                      If NULL, the function returns kStatus_SSS_Success without doing anything.
 *
 * @return kStatus_SSS_Success on success, error code otherwise.
 *         If pSession is NULL, kStatus_SSS_Success is returned.
 */
sss_status_t nx_auth_plain_session_close(sss_nx_session_t *pSession);

/**
 * @brief Establishes a mutually authenticated secure session using the
 *        AES-based Symmetric Three-Pass Mutual Authentication protocol.
 *
 * Performs AES-based mutual authentication between the host and the NX secure
 * authenticator using the Symmetric Three-Pass Mutual Authentication protocol.
 * Upon successful authentication, AES-128/256 session keys are derived
 * and used to establish an EV2 encrypted and MAC-protected secure messaging
 * channel for all subsequent communication.
 *
 * @param[out] pSession                Double pointer to the session object to be initialized.
 *                                     Must not be NULL. On success, points to the active session.
 * @param[in]  skip_select_application If set to 1, the NDEF Application will not be selected
 *                                     during session open. This is required when opening a session
 *                                     via the I2C interface when using the NFC Pause feature.
 *
 * @return kStatus_SSS_Success on success, error code otherwise.
 *
 * @note Call nx_auth_symmetric_session_close() to release all resources,
 *       including host session and key store, when done.
 */
sss_status_t nx_auth_symmetric_session_open(sss_nx_session_t **pSession, uint8_t skip_select_application);

/**
 * @brief Close a symmetric key authenticated session with the authenticator device.
 *
 * Releases resources associated with the symmetric session,
 * including the host session, key store, and authentication context keys.
 * All cleanup steps are always executed regardless of intermediate failures.
 * Safe to call with NULL pointer.
 *
 * @param[in] pSession  Pointer to the session object to be closed.
 *                      If NULL, host resources are still cleaned up and
 *                      kStatus_SSS_Success is returned.
 *
 * @return kStatus_SSS_Success on success, error code of sss_session_close() otherwise.
 *         Host session and key store cleanup is always attempted regardless of return value.
 */
sss_status_t nx_auth_symmetric_session_close(sss_nx_session_t *pSession);

/**
 * @brief Establishes a mutually authenticated secure session using the SIGMA-I protocol.
 *
 * SIGMA-I (Sign-and-MAc) is a PKI-based authentication protocol that performs
 * mutual authentication between the host and the NX secure authenticator using
 * asymmetric cryptography (EC NIST-P curves). Upon successful authentication,
 * a symmetric EV2 secure messaging channel is established to protect all
 * subsequent communication.
 *
 * Authentication flow:
 *  1. Ephemeral EC key pairs are generated on both sides.
 *  2. Each party signs the exchange using its leaf certificate private key.
 *  3. Signatures are verified against the peer's leaf certificate public key.
 *  4. A shared session secret is derived via ECDH and used to establish
 *     AES-128/256 EV2 encrypted and MAC-protected secure messaging.
 *
 * @param[out] pSession                Pointer to receive the active session handle.
 * @param[in]  skip_select_application If set to 1, the NDEF Application will not be selected
 *                                     during session open. This is required when opening a session
 *                                     via the I2C interface when using the NFC Pause feature.
 *
 * @return kStatus_SSS_Success on successful session establishment,
 *         kStatus_SSS_Fail otherwise.
 */
sss_status_t nx_auth_sigma_i_session_open(sss_nx_session_t **pSession, uint8_t skip_select_application);

/**
 * @brief Close a SIGMA-I authenticated session with the authenticator device.
 *
 * Releases resources associated with the SIGMA-I session,
 * including the host session, key store, and all asymmetric key objects
 * (ephemeral keys, leaf certificate keys, KDF keys, session keys).
 * All cleanup steps are always executed regardless of intermediate failures.
 * Safe to call with NULL pointer.
 *
 * @param[in] pSession  Pointer to the session object to be closed.
 *                      If NULL, host resources are still cleaned up and
 *                      kStatus_SSS_Success is returned.
 *
 * @return kStatus_SSS_Success on success, error code of sss_session_close() otherwise.
 *         Host session and key store cleanup is always attempted regardless of return value.
 */
sss_status_t nx_auth_sigma_i_session_close(sss_nx_session_t *pSession);

#endif /* APP_AUTH_DEVICE_H_ */
