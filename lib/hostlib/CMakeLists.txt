#
# Copyright 2022-2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

IF(SSS_HAVE_NX_TYPE)
    ADD_SUBDIRECTORY(nx_apdu)
    ADD_SUBDIRECTORY(nx_utils)
ENDIF()

ADD_SUBDIRECTORY(smCom)

IF((SSS_HAVE_HOST_PCLINUX OR SSS_HAVE_HOST_RASPBIAN) AND SSS_HAVE_SMCOM_T1OI2C_GP1_0)
	ADD_SUBDIRECTORY(smCom/T1oI2C/example/linux)
ENDIF()