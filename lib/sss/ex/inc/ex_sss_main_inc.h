/*
 *
 * Copyright 2019-2020, 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Common, Re-Usable main implementation */
/* Include this header file only once in the application */

/*
 *  Applications control the boot flow by defining these macros.
 *
 *
 *  - EX_SSS_BOOT_PCONTEXT : Pointer to ex_sss_boot_ctx_t
 *      This allows that boot framework do not blindly rely on
 *      global variables.
 *
 *  - EX_SSS_BOOT_EXPOSE_ARGC_ARGV : Expose ARGC & ARGV from Command
 *      line to Application.
 *      When running from PC/Linux/OSX, command line arguments allow
 *      to choose extra command line parameters, e.g. Input/Output
 *      certificate or signing/verifying data.
 *      But on embedded platforms, such feature is not possible to
 *      achieve.
 *
 *  Optional variables:
 *
 *  - EX_SSS_BOOT_RTOS_STACK_SIZE : For RTOS based system,
 *      this is over-ridden and passed to RTOS based example
 *      boot up.  It sets value needed for new task.
 *      Please note, FREE RTOS will reserve
 *      EX_SSS_BOOT_RTOS_STACK_SIZE * sizeof(UBaseType_t)
 *      bytes.
 *
 *  - EX_SSS_BOOT_OPEN_HOST_SESSION : For examples that do not
 *      need host side implementation, his allows to skip opening
 *      the host session. (Host session is needed to either re-verify
 *      test data at host, or for EV2 secure messaging).
 *      By default this is enabled.
 *
 *
 */

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if (defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)) || \
    (defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S))
#include "platform.h"
#endif

#include <string.h> /* memset */

#include "nx_Pkg_Ver.h"
#include "string.h" /* memset */
#include <limits.h>

#if defined(USE_RTOS) && USE_RTOS == 1
#ifndef INC_FREERTOS_H /* Header guard of FreeRTOS */
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#endif /* INC_FREERTOS_H */
#include "task.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include "fsl_sss_mbedtls_apis.h"
#endif /* SSS_HAVE_HOSTCRYPTO_MBEDTLS */

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include "fsl_sss_openssl_apis.h"
#endif /* SSS_HAVE_HOSTCRYPTO_OPENSSL */

#if SSS_HAVE_NX_TYPE
#include "fsl_sss_nx_apis.h"
#endif /* SSS_HAVE_NX_TYPE */

#ifdef EX_SSS_BOOT_PCONTEXT
#define PCONTEXT EX_SSS_BOOT_PCONTEXT
#else
#define PCONTEXT (NULL)
#endif

#if !defined(EX_SSS_BOOT_EXPOSE_ARGC_ARGV)
#error EX_SSS_BOOT_EXPOSE_ARGC_ARGV must be set to 0 or 1
#endif

#if EX_SSS_BOOT_EXPOSE_ARGC_ARGV
static int gex_sss_argc;
static const char **gex_sss_argv;
#endif

#if !defined(EX_SSS_BOOT_OPEN_HOST_SESSION)
#define EX_SSS_BOOT_OPEN_HOST_SESSION 1
#endif

#if !defined(EX_SSS_BOOT_RTOS_STACK_SIZE)
#define EX_SSS_BOOT_RTOS_STACK_SIZE 8500
#endif

#if defined(USE_RTOS) && USE_RTOS == 1
static TaskHandle_t gSSSExRtosTaskHandle = NULL;
static void sss_ex_rtos_task(void *ctx);
#endif /* RTOS */

int main(int argc, const char *argv[])
{
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    char *portName      = NULL;

#if EX_SSS_BOOT_EXPOSE_ARGC_ARGV
    gex_sss_argc = argc;
    gex_sss_argv = argv;
#endif // EX_SSS_BOOT_EXPOSE_ARGC_ARGV

    /* Initalize the embedded (baremetal) platform */
#if (defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)) || \
    (defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S))
    platform_boot_direct();
    platform_init_hardware();
#endif

    LOG_I(NX_PKG_PROD_NAME_VER_FULL);

#ifdef EX_SSS_BOOT_PCONTEXT
    memset((EX_SSS_BOOT_PCONTEXT), 0, sizeof(*(EX_SSS_BOOT_PCONTEXT)));
#endif // EX_SSS_BOOT_PCONTEXT

#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
    status = ex_sss_boot_connectstring(argc, argv, &portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_boot_connectstring Failed");
        goto cleanup;
    }
#endif // Non-embedded

    /* Initialise Logging locks */
    if (nLog_Init() != 0) {
        LOG_E("Lock initialisation failed");
    }

#if defined(EX_SSS_BOOT_SKIP_SELECT_FILE) && (EX_SSS_BOOT_SKIP_SELECT_FILE == 1)
    (PCONTEXT)->nx_open_ctx.skip_select_file = 1;
#endif

#if defined(USE_RTOS) && USE_RTOS == 1
    if (xTaskCreate(&sss_ex_rtos_task,
            "sss_ex_rtos_task",
            EX_SSS_BOOT_RTOS_STACK_SIZE,
            (void *)portName,
            (tskIDLE_PRIORITY),
            &gSSSExRtosTaskHandle) != pdPASS) {
        LOG_E("Task creation failed!.\r\n");
        while (1)
            ;
    }

    /* Run RTOS */
    vTaskStartScheduler();

#else /* No RTOS, No Embedded */

#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
    if (ex_sss_boot_isHelp(portName)) {
        memset(PCONTEXT, 0, sizeof(*PCONTEXT));
#if EX_SSS_BOOT_EXPOSE_ARGC_ARGV
        /* so that tool can fetchup last value */
        if (gex_sss_argc > (INT_MAX - 1)) {
            status = kStatus_SSS_Fail;
            goto cleanup;
        }
        gex_sss_argc++;
#endif // EX_SSS_BOOT_EXPOSE_ARGC_ARGV
        goto before_ex_sss_entry;
    }
#endif // Non-embedded

    status = ex_sss_boot_open(PCONTEXT, portName);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_session_open Failed");
        goto cleanup;
    }

    if (kType_SSS_SubSystem_NONE == ((PCONTEXT)->session.subsystem)) {
        /* Nothing to do. Device is not opened
         * This is needed for the case when we open a generic communication
         * channel, without being specific to SE
         */
    }
    else {
        status = ex_sss_key_store_and_object_init((PCONTEXT));
        if (kStatus_SSS_Success != status) {
            LOG_E("ex_sss_key_store_and_object_init Failed");
            goto cleanup;
        }
    }

#if EX_SSS_BOOT_OPEN_HOST_SESSION && SSS_HAVE_HOSTCRYPTO_ANY
    ex_sss_boot_open_host_session((PCONTEXT));
#endif

#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
before_ex_sss_entry:
#endif

    status = ex_sss_entry((PCONTEXT));
    LOG_I("ex_sss Finished");
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_entry Failed");
        goto cleanup;
    }
#endif /* No RTOS, No Embedded */
    // Delete locks for pthreads
    nLog_DeInit();
    goto cleanup;

cleanup:
#ifdef EX_SSS_BOOT_PCONTEXT
    ex_sss_session_close((EX_SSS_BOOT_PCONTEXT));
#endif
    if (kStatus_SSS_Success == status) {
        ret = 0;
#if (defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)) || \
    (defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S))
        platform_success_indicator();
#endif
    }
    else {
        LOG_E("!ERROR! ret != 0.");
        ret = 1;
#if (defined(SSS_HAVE_HOST_FRDMK64F) && (SSS_HAVE_HOST_FRDMK64F)) || \
    (defined(SSS_HAVE_HOST_LPCXPRESSO55S) && (SSS_HAVE_HOST_LPCXPRESSO55S))
        platform_failure_indicator();
#endif
    }
#if defined(_MSC_VER)
    if (portName) {
        char *dummy_portName = NULL;
        size_t dummy_sz      = 0;
        _dupenv_s(&dummy_portName, &dummy_sz, EX_SSS_BOOT_SSS_PORT);
        if (NULL != dummy_portName) {
            free(dummy_portName);
            if ((argc > 1)        /* Alteast 1 cli argument */
                && (argv != NULL) /* argv not null */
                && (portName == (char *)argv[argc - 1])) {
                // portName comes from argv;
            }
            else {
                free(portName);
            }
        }
    }
#endif // _MSC_VER

    return ret;
}

#if defined(USE_RTOS) && USE_RTOS == 1
static void sss_ex_rtos_task(void *ctx)
{
    LOG_I("sss_ex_rtos_task Started.");
    sss_status_t status;

    status = ex_sss_boot_open(PCONTEXT, (const char *)ctx);

    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_session_open Failed.");
        goto exit;
    }

    status = ex_sss_key_store_and_object_init((PCONTEXT));

    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_key_store_and_object_init Failed");
        goto exit;
    }

    status = ex_sss_entry((PCONTEXT));

    LOG_I("ex_sss Finished");
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_entry Failed");
    }

    ex_sss_session_close(PCONTEXT);
    /* Delete locks for FreeRtos*/
    nLog_DeInit();

exit:
#if defined(_MSC_VER) || defined(__linux__) || defined(__MINGW32__) || defined(__MINGW64__)
    if (kStatus_SSS_Success == status) {
        exit(0);
    }
    else {
        exit(1);
    }
#else
    vTaskDelete(NULL);
#endif
}

#endif /* No RTOS, No Embedded */
