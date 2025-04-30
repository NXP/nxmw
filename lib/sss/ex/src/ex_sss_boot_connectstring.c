/*
 *
 * Copyright 2019-2020, 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/** @file
 *
 * ex_sss_boot_connectstring.c:  *The purpose and scope of this file*
 *
 * Project:  SecureIoTMW-Debug@appboot-top-eclipse_x86
 *
 * $Date: Mar 10, 2019 $
 * $Author: ing05193 $
 * $Revision$
 */

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ex_sss_boot.h"
#include "nxLog_msg.h"
#include "sm_types.h"
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#include <Crtdbg.h>
#endif

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Global and Static Variables
 * Total Size: NNNbytes
 * ***************************************************************************************************************** */

const char gszCOMPortDefault[] = EX_SSS_BOOT_SSS_COMPORT_DEFAULT;
const char gszReaderDefault[]  = EX_SSS_BOOT_SSS_PCSC_READER_DEFAULT;

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

sss_status_t ex_sss_boot_connectstring(int argc, const char *argv[], char **pPortName)
{
    char *portName      = NULL;
    sss_status_t status = kStatus_SSS_Fail;
#if defined(_WIN32) && defined(WIN32) && defined(DEBUG)
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
    bool last_is_help = FALSE;
    if (argv != NULL) {
        LOG_I("Running %s", argv[0]);
    }
    if (argc > 1                  /* Alteast 1 cli argument */
        && argv != NULL           /* argv not null */
        && argv[argc - 1] != NULL /* Last parameter exists */
    ) {
        if (0 == strncmp("--help", argv[argc - 1], sizeof("--help"))) {
            last_is_help = TRUE;
        }
    }
    if (TRUE == last_is_help) {
        if (NULL == pPortName) {
            LOG_E("pPortName is NULL");
            return status;
        }
        *pPortName = (char *)argv[argc - 1]; /* --help */
        status     = kStatus_SSS_Success;
        return status;
    }
    if (argc > 1                    /* Alteast 1 cli argument */
        && argv != NULL             /* argv not null */
        && argv[argc - 1] != NULL   /* Last parameter exists */
        && argv[argc - 1][0] != '-' /* Not something like -h / --help */
    ) {
        portName = (char *)argv[argc - 1]; /* last entry, deemed as port name */
        LOG_I("Using PortName='%s' (CLI)", portName);
    }
    else
#endif // Non embedded
    {
#if defined(_MSC_VER)
        char *portName_env = NULL;
        size_t sz          = 0;
        _dupenv_s(&portName_env, &sz, EX_SSS_BOOT_SSS_PORT);
#else
        const char *portName_env = getenv(EX_SSS_BOOT_SSS_PORT);
#endif
        if (portName_env != NULL) {
            portName = (char *)portName_env;
            LOG_I("Using PortName='%s' (ENV: %s=%s)", portName, EX_SSS_BOOT_SSS_PORT, portName);
        }
    }

    if (portName == NULL) {
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
        portName = (char *)gszCOMPortDefault;
        LOG_I("Using PortName='%s' (gszCOMPortDefault)", portName);
#elif defined(SSS_HAVE_SMCOM_PCSC) && (SSS_HAVE_SMCOM_PCSC)
        portName                 = (char *)gszReaderDefault;
#endif

#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
        LOG_I(
            "If you want to over-ride the selection, use ENV=%s or pass in "
            "command line arguments.",
            EX_SSS_BOOT_SSS_PORT);
#endif // Non embedded
    }
    status = kStatus_SSS_Success;

    if (status == kStatus_SSS_Success && pPortName != NULL) {
        *pPortName = (char *)portName;
    }
    return status;
}

bool ex_sss_boot_isSerialPortName(const char *portName)
{
    bool is_vcom = FALSE;
#if defined(SSS_HAVE_SMCOM_VCOM) && (SSS_HAVE_SMCOM_VCOM)
    if (portName == NULL) {
        is_vcom = FALSE;
    }
    else if (0 == strncmp("COM", portName, sizeof("COM") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("\\\\.\\COM", portName, sizeof("\\\\.\\COM") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("/tty/", portName, sizeof("/tty/") - 1)) {
        is_vcom = TRUE;
    }
    else if (0 == strncmp("/dev/tty", portName, sizeof("/dev/tty") - 1)) {
        is_vcom = TRUE;
    }
#endif
    return is_vcom;
}

bool ex_sss_boot_isHelp(const char *argname)
{
    bool last_is_help = FALSE;

    if (NULL != argname && (0 == strncmp("--help", argname, sizeof("--help")))) {
        last_is_help = TRUE;
    }
    return last_is_help;
}

/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */
