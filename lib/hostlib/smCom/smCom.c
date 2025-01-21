/*
 *
 * Copyright 2016-2020, 2022-2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * Implements installable communication layer to exchange APDU's between Host and Secure Module.
 * Allows the top half of the Host Library to be independent of the actual interconnect
 * between Host and Secure Module
 */
#include <stdio.h>
#include "smCom.h"
#include "nxLog_msg.h"

#if defined(USE_RTOS) && (USE_RTOS == 1)
#include "FreeRTOS.h"
#include "semphr.h"
#endif

#if defined(USE_RTOS) && (USE_RTOS == 1)
static SemaphoreHandle_t gSmComlock;
#elif __GNUC__ && \
    ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) || \
    (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
    (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
#include <pthread.h>
/* Only for base session with os */
static pthread_mutex_t gSmComlock;
#endif

#if __GNUC__ && \
    ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) || \
    (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
    (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
#define USE_LOCK 1
#else
#define USE_LOCK 0
#endif

// If enabled, count how much time is used for smCom_TransceiveRaw.
#define SMCOM_DEBUG_TIME 0

#if SMCOM_DEBUG_TIME
#if ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) || \
    (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
    (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
    /* Non-embedded platforms */
#include <time.h>
#endif
#endif // SMCOM_DEBUG_TIME

#if defined(USE_RTOS) && (USE_RTOS == 1)
#define LOCK_TXN()                                             \
    LOG_D("Trying to Acquire Lock");                           \
    if (xSemaphoreTake(gSmComlock, portMAX_DELAY) == pdTRUE) { \
        LOG_D("LOCK Acquired");                                \
    }                                                          \
    else {                                                     \
        LOG_D("LOCK Acquisition failed");                      \
    }
#define UNLOCK_TXN()                            \
    LOG_D("Trying to Released Lock");           \
    if (xSemaphoreGive(gSmComlock) == pdTRUE) { \
        LOG_D("LOCK Released");                 \
    }                                           \
    else {                                      \
        LOG_D("LOCK Releasing failed");         \
    }
#elif __GNUC__ && \
    ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) || \
    (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
    (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
#define LOCK_TXN()                                               \
    LOG_D("Trying to Acquire Lock thread: %ld", pthread_self()); \
    if (0 != pthread_mutex_lock(&gSmComlock)) {                  \
        LOG_E("pthread_mutex_lock failed");                      \
    }                                                            \
    LOG_D("LOCK Acquired by thread: %ld", pthread_self());

#define UNLOCK_TXN()                                                 \
    LOG_D("Trying to Released Lock by thread: %ld", pthread_self()); \
    if (0 != pthread_mutex_unlock(&gSmComlock)) {                    \
        LOG_E("pthread_mutex_lock failed");                          \
    }                                                                \
    LOG_D("LOCK Released by thread: %ld", pthread_self());
#else
#define LOCK_TXN() LOG_D("no lock mode");
#define UNLOCK_TXN() LOG_D("no lock mode");
#endif

static ApduTransceiveFunction_t pSmCom_Transceive       = NULL;
static ApduTransceiveRawFunction_t pSmCom_TransceiveRaw = NULL;

/**
 * Install interconnect and protocol specific implementation of APDU transfer functions.
 *
 */
U16 smCom_Init(ApduTransceiveFunction_t pTransceive, ApduTransceiveRawFunction_t pTransceiveRaw)
{
    U16 ret = SMCOM_COM_INIT_FAILED;
    if ((NULL == pTransceive) || (NULL == pTransceiveRaw)) {
        goto exit;
    }
#if defined(USE_RTOS) && (USE_RTOS == 1)
    gSmComlock = xSemaphoreCreateMutex();
    if (gSmComlock == NULL) {
        LOG_E("\n xSemaphoreCreateMutex failed");
        goto exit;
    }
#elif __GNUC__ && \
    ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) || \
    (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
    (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
    if (pthread_mutex_init(&gSmComlock, NULL) != 0) {
        LOG_E("\n mutex init has failed");
        goto exit;
    }
#endif
    pSmCom_Transceive    = pTransceive;
    pSmCom_TransceiveRaw = pTransceiveRaw;
    ret                  = SMCOM_OK;
exit:
    return ret;
}

void smCom_DeInit(void)
{
#if defined(USE_RTOS) && (USE_RTOS == 1)
    if (gSmComlock != NULL) {
        vSemaphoreDelete(gSmComlock);
        gSmComlock = NULL;
    }
#elif __GNUC__ && \
    ((defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS)) || \
    (defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64)) || \
    (defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)))
    if (0 != pthread_mutex_destroy(&gSmComlock)) {
        LOG_E("pthread_mutex_destroy failed");
    }
#endif
    pSmCom_Transceive    = NULL;
    pSmCom_TransceiveRaw = NULL;
}

/**
 * Exchanges APDU without interpreting the message exchanged
 *
 * @param[in] pTx          Command to be sent to secure module
 * @param[in] txLen        Length of command to be sent
 * @param[in,out] pRx      IN: Buffer to contain response; OUT: Response received from secure module
 * @param[in,out] pRxLen   IN: [TBD]; OUT: Length of response received
 *
 * @retval ::SMCOM_OK          Operation successful
 * @retval ::SMCOM_SND_FAILED  Send Failed
 * @retval ::SMCOM_RCV_FAILED  Receive Failed
 */
U32 smCom_TransceiveRaw(void *conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    U32 ret = SMCOM_NO_PRIOR_INIT;

#if SMCOM_DEBUG_TIME
#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
    /* Non-Embedded platforms */
    clock_t t;
    double time_taken;

    t = clock();
#else
#endif
#endif // SMCOM_DEBUG_TIME

    if (pSmCom_TransceiveRaw != NULL) {
        LOCK_TXN();
        ret = pSmCom_TransceiveRaw(conn_ctx, pTx, txLen, pRx, pRxLen);
        UNLOCK_TXN();
    }

#if SMCOM_DEBUG_TIME
#if defined(SSS_HAVE_HOST_PCWINDOWS) && (SSS_HAVE_HOST_PCWINDOWS) || \
    defined(SSS_HAVE_HOST_PCLINUX64) && (SSS_HAVE_HOST_PCLINUX64) || \
    defined(SSS_HAVE_HOST_RASPBIAN) && (SSS_HAVE_HOST_RASPBIAN)
    /* Non-Embedded platforms */
    t          = clock() - t;
    time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds
    LOG_I("smCom_TransceiveRaw() took %f ticks, %f seconds to execute, CLOCKS_PER_SEC %f\n",
        (double)t,
        time_taken,
        (double)CLOCKS_PER_SEC);
#else
#endif
#endif // SMCOM_DEBUG_TIME

    return ret;
}
