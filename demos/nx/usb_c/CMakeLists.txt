#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

ADD_SUBDIRECTORY(usb_c_responder_auth)
ADD_SUBDIRECTORY(usb_c_initiator_auth)
ADD_SUBDIRECTORY(usb_c_provisioning)
ADD_SUBDIRECTORY(usb_c_auth)

IF(NXPInternal)
    ADD_SUBDIRECTORY(tst)
ENDIF()
