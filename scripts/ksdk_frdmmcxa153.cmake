#
# Copyright 2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
# ksdk_frdmmcxa153.cmake

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXA/MCXA153/gcc/startup_MCXA153.S
    ${NXMW_TOP_DIR}/../mcuxsdk/components/misc_utilities/fsl_syscall_stub.c
)

ADD_DEFINITIONS(
    -DCPU_MCXA153VLH
    -DMCXA
    -DPRINTF_ADVANCED_ENABLE=1
    -DPRINTF_FLOAT_ENABLE=0
    -DSCANF_FLOAT_ENABLE=0
    -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1
    -DCR_INTEGER_PRINTF
)

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_DEFINITIONS(-DFSL_RTOS_FREE_RTOS)
ENDIF()

INCLUDE_DIRECTORIES(
    ${NXMW_TOP_DIR}/boards/frdmmcxa153/
)

SET(_FLAGS_CPU " -mcpu=cortex-m33+nodsp -mthumb -mfloat-abi=soft ")
SET(_FLAGS_L_SPECS "--specs=nano.specs --specs=nosys.specs -Wl,--print-memory-usage")

IF(SSS_HAVE_RTOS_FREERTOS)
    SET(
        _FLAGS_L_MEM
        " \
    -Xlinker --defsym=__stack_size__=0x2000 \
    -Xlinker --defsym=__heap_size__=0x8000 "
    )
ENDIF()

IF(SSS_HAVE_RTOS_DEFAULT)
    IF(SSS_HAVE_AUTH_SYMM_AUTH)
        SET(
            _FLAGS_L_MEM
            " \
        -Xlinker --defsym=__stack_size__=0x2800 \
        -Xlinker --defsym=__heap_size__=0x3000 "
        )
    ELSE()
        SET(
            _FLAGS_L_MEM
            " \
        -Xlinker --defsym=__stack_size__=0x2900 \
        -Xlinker --defsym=__heap_size__=0x3500 "
        )
    ENDIF()
ENDIF()
SET(
    _FLAGS_L_LD
    " \
-T${NXMW_TOP_DIR}/boards/frdmmcxa153/linker/MCXA153_flash.ld \
-static "
)
