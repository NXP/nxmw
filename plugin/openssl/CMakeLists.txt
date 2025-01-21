#
# Copyright 2019,2020 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

PROJECT(sss_engine)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    engine/src/ax_sssEngine_main.c
    engine/src/ax_sssEngine_rand.c
    engine/src/ax_sssEngine_ecc.c
)


ADD_LIBRARY(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_files})

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
    SSS_APIs
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ${OPENSSL_LIBRARIES}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${NXMW_TOP_DIR}/lib/sss/ex/inc
    PUBLIC engine/inc
)

IF(
    "${CMAKE_SYSTEM_NAME}"
    STREQUAL
    "WindowsStore"
)
    SET_PROPERTY(TARGET ${PROJECT_NAME} PROPERTY VS_WINRT_COMPONENT TRUE)
ENDIF()

IF(SSS_HAVE_HOST_WIN10IOT)
    SET_TARGET_PROPERTIES(
        ${PROJECT_NAME}
        PROPERTIES LINK_FLAGS_RELEASE
                   "/defaultlib:vccorlib.lib /defaultlib:msvcrt.lib /wholearchive:smComWin10IoTWrapper.lib"
    )
    SET_TARGET_PROPERTIES(
        ${PROJECT_NAME}
        PROPERTIES LINK_FLAGS_DEBUG
                   "/defaultlib:vccorlibd.lib /defaultlib:msvcrtd.lib /wholearchive:smComWin10IoTWrapper.lib"
    )
ENDIF()

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${NXMW_TOP_DIR}/plugin/openssl/bin
    COMMENT "Copy dll to ${NXMW_TOP_DIR}/plugin/openssl/bin"
)

IF((SSS_HAVE_HOST_LINUX_LIKE) AND NOT(NXPInternal))
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
    ADD_CUSTOM_COMMAND(
        TARGET ${PROJECT_NAME}
        POST_BUILD
        COMMAND cp $<TARGET_FILE:${PROJECT_NAME}> /usr/local/lib/
        COMMENT "Copying lib${PROJECT_NAME}.so to /usr/local/lib/"
    )
ENDIF()
