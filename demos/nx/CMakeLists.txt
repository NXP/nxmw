#
# Copyright 2022-2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

IF(SSS_HAVE_ALL_AUTH_CODE_ENABLED AND SSS_HAVE_NX_TYPE AND NOT SSS_HAVE_NX_TYPE_NX_PICC AND (SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX64 OR SSS_HAVE_HOST_RASPBIAN))
    IF (SSS_HAVE_HOSTCRYPTO_MBEDTLS OR SSS_HAVE_HOSTCRYPTO_OPENSSL)
        ADD_SUBDIRECTORY(nx_cli_tool)
    ENDIF()
ENDIF()

IF (NOT (SSS_HAVE_NX_TYPE_NX_PICC OR (SSS_HAVE_HOST_FRDMMCXA153 AND SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED)))
    ADD_SUBDIRECTORY(md)
    ADD_SUBDIRECTORY(rng)
    ADD_SUBDIRECTORY(ecc)
    ADD_SUBDIRECTORY(hmac)
    ADD_SUBDIRECTORY(symmetric)
    IF (SSS_HAVE_HOSTCRYPTO_ANY)
        ADD_SUBDIRECTORY(ecdh)
        ADD_SUBDIRECTORY(hkdf)
    ENDIF ()
ENDIF()


IF(SSS_HAVE_NX_TYPE)
    ADD_SUBDIRECTORY(nx_Minimal)
    ADD_SUBDIRECTORY(getVersion)

	IF ((SSS_HAVE_HOST_FRDMMCXA153 OR SSS_HAVE_HOST_FRDMMCXN947) AND SSS_HAVE_AUTH_NONE)
        IF (NOT SSS_HAVE_RTOS_FREERTOS)
		    ADD_SUBDIRECTORY(host_coprocessor)
        ENDIF()
    ENDIF()

    IF (SSS_HAVE_HOST_FRDMMCXN947 AND SSS_HAVE_HOSTCRYPTO_MBEDTLS AND SSS_HAVE_AUTH_NONE AND SSS_HAVE_ALL_AUTH_CODE_ENABLED)
        IF (NOT SSS_HAVE_RTOS_FREERTOS)
            # Currently supports just one host, i.e. FRDM-MCXN947, can be extended for other embedded devices
            ADD_SUBDIRECTORY(multiple_sessions)
            ADD_SUBDIRECTORY(ecc_standalone)
        ENDIF()
    ENDIF()

    IF (NOT (SSS_HAVE_NX_TYPE_NX_PICC OR (SSS_HAVE_HOST_FRDMMCXA153 AND SSS_HAVE_AUTH_SYMM_DIVERSIFY_ENABLED)))
        ADD_SUBDIRECTORY(md_using_slots)
        ADD_SUBDIRECTORY(cmac_using_slots)
        ADD_SUBDIRECTORY(cert_repo)
        ADD_SUBDIRECTORY(sdm)
        ADD_SUBDIRECTORY(cert_access_right)

        IF (SSS_HAVE_AUTH_SIGMA_I_VERIFIER OR SSS_HAVE_AUTH_SIGMA_I_PROVER OR SSS_HAVE_AUTH_SYMM_AUTH)
            ADD_SUBDIRECTORY(fileMgnt)
            ADD_SUBDIRECTORY(getCardUID)
            ADD_SUBDIRECTORY(setConfig)
			IF (NOT (SSS_HAVE_HOST_FRDMMCXA153 AND SSS_HAVE_MBEDTLS_3_X))
            	ADD_SUBDIRECTORY(getConfig)
            	ADD_SUBDIRECTORY(usb_c)
			ENDIF()
            ADD_SUBDIRECTORY(counter_file)

            IF (NOT SSS_HAVE_HOST_EMBEDDED)
                ADD_SUBDIRECTORY(nx_tool_setconfig)
            ENDIF()

            IF (SSS_HAVE_ALL_AUTH_CODE_ENABLED)
                IF (SSS_HAVE_SMCOM_VCOM OR SSS_HAVE_SMCOM_T1OI2C_GP1_0)
                    IF (NOT SSS_HAVE_RTOS_FREERTOS)
                        ADD_SUBDIRECTORY(gpio_notif)
                    ENDIF()
                ENDIF()
            ENDIF()

            IF(SSS_HAVE_AUTH_SYMM_DIVERSIFY_DISABLED)
                ADD_SUBDIRECTORY(diversify_key_perso)
            ENDIF()
        ENDIF()

        IF((SSS_HAVE_SMCOM_VCOM OR SSS_HAVE_SMCOM_T1OI2C_GP1_0) AND SSS_HAVE_AUTH_NONE AND SSS_HAVE_SECURE_TUNNELING_NONE)
            ADD_SUBDIRECTORY(dual_interfaces)
        ENDIF()

        IF(SSS_HAVE_SMCOM_VCOM OR SSS_HAVE_SMCOM_T1OI2C_GP1_0 OR (SSS_HAVE_HOST_PCWINDOWS AND SSS_HAVE_SMCOM_PCSC))
                ADD_SUBDIRECTORY(gpio)
        ENDIF()

        IF(SSS_HAVE_AUTH_ASYMM_HOST_PK_CACHE_ENABLED AND (SSS_HAVE_AUTH_SIGMA_I_VERIFIER OR SSS_HAVE_AUTH_SIGMA_I_PROVER) AND (NOT SSS_HAVE_HOST_EMBEDDED))
            ADD_SUBDIRECTORY(cert_cache)
        ENDIF()

        IF(SSS_HAVE_HOSTCRYPTO_MBEDTLS)
            IF (NOT ((SSS_HAVE_AUTH_SIGMA_I_VERIFIER OR SSS_HAVE_AUTH_SIGMA_I_PROVER OR SSS_HAVE_AUTH_NONE) AND SSS_HAVE_HOST_FRDMMCXA153))
                ADD_SUBDIRECTORY(sa_qi)
            ENDIF()
        ENDIF()

        IF(SSS_HAVE_HOST_PCWINDOWS OR SSS_HAVE_HOST_PCLINUX64 OR SSS_HAVE_HOST_RASPBIAN OR SSS_HAVE_HOST_EMBEDDED)
            IF (SSS_HAVE_AUTH_SYMM_AUTH)
                ADD_SUBDIRECTORY(nx_Personalization)
            ENDIF()
        ENDIF()

        IF(SSS_HAVE_AUTH_SYMM_AUTH)
            ADD_SUBDIRECTORY(multiple_symm_auth)
            ADD_SUBDIRECTORY(update_key)
        ENDIF()
    ENDIF()

    IF (SSS_HAVE_NX_TYPE_NX_PICC AND SSS_HAVE_AUTH_NONE AND SSS_HAVE_HOSTCRYPTO_ANY)
        ADD_SUBDIRECTORY(originality_check)
    ENDIF()

    IF(SSS_HAVE_MBEDTLS_3_X AND SSS_HAVE_MBEDTLS_ALT_SSS AND SSS_HAVE_HOSTCRYPTO_MBEDTLS)
        ADD_SUBDIRECTORY(mbedtls_3_x_alt)
    ENDIF()
ENDIF()

IF(SSS_HAVE_KSDK AND SSS_HAVE_RTOS_DEFAULT AND SSS_HAVE_SMCOM_T1OI2C_GP1_0 AND SSS_HAVE_HOST_EMBEDDED)
    IF(NXPProprietary)
        ADD_SUBDIRECTORY(vcom/ksdk)
    ENDIF()
ENDIF()

IF (SSS_HAVE_NX_TYPE AND SSS_HAVE_SMCOM_T1OI2C_GP1_0)
    ADD_SUBDIRECTORY(nx_release_req_cmd)
    ADD_SUBDIRECTORY(nx_deep_pwr_down)
ENDIF()


