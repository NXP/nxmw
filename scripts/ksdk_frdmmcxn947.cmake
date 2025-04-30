#
# Copyright 2024-2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
# ksdk_frdmmcxn947.cmake

FILE(
    GLOB
    KSDK_STARTUP_FILE
    ${NXMW_TOP_DIR}/../mcuxsdk/devices/MCX/MCXN/MCXN947/gcc/startup_MCXN947_cm33_core0.S
)

ADD_DEFINITIONS(
    -DCPU_MCXN947VDF_cm33_core0
    -DMCXN
    -DPRINTF_ADVANCED_ENABLE=1
    -DPRINTF_FLOAT_ENABLE=0
    -DSCANF_FLOAT_ENABLE=0
    -DFSL_SDK_DRIVER_QUICK_ACCESS_ENABLE=1
    -DCR_INTEGER_PRINTF
    -DLPC_ENET
    -DEXAMPLE_USE_MCXN_ENET_PORT
)

IF(SSS_HAVE_RTOS_FREERTOS)
    ADD_DEFINITIONS(-DFSL_RTOS_FREE_RTOS)
ENDIF()

INCLUDE_DIRECTORIES(boards/frdmmcxn947)

SET(_FLAGS_CPU " -mcpu=cortex-m33 -mthumb -mfloat-abi=hard ")
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
    SET(
        _FLAGS_L_MEM
        " \
    -Xlinker --defsym=__stack_size__=0x5000 \
    -Xlinker --defsym=__heap_size__=0x4000 "
    )
ENDIF()

SET(
    _FLAGS_L_LD
    " \
-T${NXMW_TOP_DIR}/boards/frdmmcxn947/linker/MCXN947_flash.ld \
-static "
)
