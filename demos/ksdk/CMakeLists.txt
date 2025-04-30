#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

IF(SSS_HAVE_KSDK AND SSS_HAVE_NX_TYPE AND SSS_HAVE_RTOS_FREERTOS)
# Currently only FRDMMCXN947 cloud demo supported
    IF (SSS_HAVE_HOST_FRDMMCXN947)
        ADD_SUBDIRECTORY(aws_jitr)
        ADD_SUBDIRECTORY(provisioning)
    ENDIF()
ENDIF()