# Copyright 2018,2020,2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

CMAKE_MINIMUM_REQUIRED(VERSION 3.5.0)

IF(
    ${CMAKE_SOURCE_DIR}
    STREQUAL
    ${CMAKE_BINARY_DIR}
)
    MESSAGE("\nUSAGE_ERROR:\n\n\tRun with cmake -S <SOURCE_DIR> -B <BUILD_DIR>\n")
    MESSAGE(
        FATAL_ERROR
        "In-source builds not allowed. Please make a new directory and run CMake from there.\n!!!IMPORTANT!!! Remove CMakeCache.txt and CMakeFiles!"
    )
ENDIF()


############ Project NX Middleware ############
PROJECT(NxMW)


# Top DIR for SE
SET(NXMW_TOP_DIR "${CMAKE_SOURCE_DIR}")

INCLUDE(scripts/cmake_options.cmake)
INCLUDE(scripts/git_version.cmake)
SET(CMAKE_MODULE_PATH "./scripts")

INCLUDE_DIRECTORIES(${CMAKE_BINARY_DIR})
SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

CONFIGURE_FILE(lib/sss/inc/fsl_sss_ftr.h.in fsl_sss_ftr.h)
CONFIGURE_FILE(scripts/cmake_options.mak.in cmake_options.mak)
CONFIGURE_FILE(scripts/cmake_options_installed.cmake.in cmake_options_installed.cmake)

INSTALL(FILES ${CMAKE_BINARY_DIR}/fsl_sss_ftr.h DESTINATION ${NXMW_INSTALL_INC_DIR})
INSTALL(FILES ${CMAKE_BINARY_DIR}/cmake_options.mak DESTINATION ${NXMW_INSTALL_SHARE_DIR})
INSTALL(FILES ${CMAKE_BINARY_DIR}/cmake_options_installed.cmake DESTINATION ${NXMW_INSTALL_SHARE_DIR})

# EXT and DOC should not be dependent on any compile time variables/depednencies
# ESPECIALLY, SSS_USE_FTR_FILE and FLOW_VERBOSE
ADD_DEFINITIONS(-DSSS_USE_FTR_FILE)
ADD_DEFINITIONS(-DmqttconfigENABLE_METRICS=0)



############ Code Coverage ############
IF(WithCodeCoverage)
    IF(CMAKE_COMPILER_IS_GNUCXX)
        INCLUDE(scripts/CodeCoverage.cmake)
        APPEND_COVERAGE_COMPILER_FLAGS()
    ENDIF()
ENDIF()



############ Logging ############
IF(SSS_HAVE_LOG_SILENT)
    MESSAGE(STATUS "FLOW_SILENT is ON!!!")
    ADD_DEFINITIONS(-DFLOW_SILENT)
ENDIF()
IF(SSS_HAVE_LOG_VERBOSE)
    MESSAGE(STATUS "FLOW_VERBOSE is ON!!!")
    ADD_DEFINITIONS(-DFLOW_VERBOSE)
ENDIF()
IF(NOT SSS_HAVE_LOG_SEGGERRTT)
    ADD_SUBDIRECTORY("${CMAKE_SOURCE_DIR}/lib/hostlib/nx_log")
ENDIF()



############ Add all modules ############
ADD_SUBDIRECTORY(lib/hostlib)
ADD_SUBDIRECTORY(lib/sss)
ADD_SUBDIRECTORY(boards)
ADD_SUBDIRECTORY(demos)
ADD_SUBDIRECTORY(plugin)


############ example init code ############
ADD_SUBDIRECTORY(lib/sss/ex/src)



############ NXP Internal ############
IF(NXPInternal)
    IF(
        "${CMAKE_CXX_COMPILER_ID}"
        STREQUAL
        "MSVC"
    )
    # Macros won't work for MSVC
    ELSE()
        ADD_SUBDIRECTORY(exhaledocs)
    ENDIF()

    CONFIGURE_FILE(tst/sss/inc/nx_tst_ftr.h.in nx_tst_ftr.h)
    ADD_SUBDIRECTORY(tst)
    ADD_SUBDIRECTORY(ext)

ENDIF()
