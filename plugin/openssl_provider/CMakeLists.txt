#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

INCLUDE_DIRECTORIES(/opt/openssl30/include/)

PROJECT(sssProvider)

FILE(
    GLOB
    ${PROJECT_NAME}_files
    provider/src/sssProvider_main.c
    provider/src/sssProvider_rand.c
    provider/src/sssProvider_ecdsa.c
    provider/src/sssProvider_store.c
    provider/src/sssProvider_file_store.c
    provider/src/sssProvider_key_mgmt_ec.c
    provider/src/sssProvider_ecdh.c
    provider/src/sssProvider_get_capabilities.c
    provider/src/*.h
)


ADD_LIBRARY(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_files})

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME}
    ex_common
)

TARGET_LINK_LIBRARIES(
    ${PROJECT_NAME} ${OPENSSL_LIBRARIES}
)

TARGET_INCLUDE_DIRECTORIES(
    ${PROJECT_NAME}
    PRIVATE ${NXMW_TOP_DIR}/lib/sss/ex/inc
    PUBLIC provider/inc
)

#ADD_DEFINITIONS(-DSSS_PROV_DISABLE_NX_RNG)

ADD_CUSTOM_COMMAND(
    TARGET ${PROJECT_NAME}
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> ${NXMW_TOP_DIR}/plugin/openssl_provider/bin
    COMMENT "Copy dll to ${NXMW_TOP_DIR}/plugin/openssl_provider/bin"
)

IF(SSS_HAVE_HOST_LINUX_LIKE)
    INSTALL(TARGETS ${PROJECT_NAME} DESTINATION lib)
ENDIF()