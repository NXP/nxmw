# Copyright 2014 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#
# ksdk_lpcxpresso55s69.cmake

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/gcc/startup_LPC55S69_cm33_core0.S
    ${KSDK_VENEER_FILES}
)

ADD_DEFINITIONS(
    -DLPC_55x
    -DA_LITTLE_ENDIAN
    -DCPU_LPC55S69JBD100_cm33_core0
    -DCPU_LPC55S69JBD100
    -DCPU_LPC55S69JBD100_cm33
    -DARM_MATH_CM33
    -D__MULTICORE_MASTER
    -DNXP_IOT_AGENT_USE_COREJSON
)

SET(_FLAGS_CPU " -mcpu=cortex-m33 -mfpu=fpv5-sp-d16 -mfloat-abi=hard ")
SET(_FLAGS_L_SPECS " --specs=nano.specs --specs=nosys.specs -Wl,--print-memory-usage")

IF(SSS_HAVE_RTOS_FREERTOS)
    SET(
        _FLAGS_L_MEM
        " \
    -Xlinker --defsym=__ram_vector_table__=1 \
    -Xlinker --defsym=__stack_size__=0x2000 \
    -Xlinker --defsym=__heap_size__=0x8000 "
    )
ENDIF()
IF(SSS_HAVE_RTOS_DEFAULT)
    SET(
        _FLAGS_L_MEM
        " \
    -Xlinker --defsym=__ram_vector_table__=1 \
    -Xlinker --defsym=__stack_size__=0x6F00 \
    -Xlinker --defsym=__heap_size__=0x4000 "
    )
ENDIF()

IF(SSS_HAVE_HOST_LPCXPRESSO55S)
    SET(_LD_FILE_ForWorld "LPC55S69_cm33_core0_flash.ld")
ENDIF()

SET(
    _FLAGS_L_LD
    "${_FLAGS_L_CMSE} \
    -T${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/gcc/${_LD_FILE_ForWorld} \
    -static "
)

LINK_DIRECTORIES(${NXMW_TOP_DIR}/../mcuxsdk/devices/LPC/LPC5500/LPC55S69/gcc)
