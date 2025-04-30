/*
 *
 * Copyright 2018,2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef NX_LOG_CONFIG_H
#define NX_LOG_CONFIG_H

/******** Default Logging ************/
/*
 * - 1 => Enable Debug level logging - for all.
 * - 0 => Disable Debug level logging.  This has to be
 *        enabled individually by other logging
 *        header/source files */
#define NX_LOG_ENABLE_DEFAULT_DEBUG 0

/* Same as NX_LOG_ENABLE_DEFAULT_DEBUG but for Info Level */
#define NX_LOG_ENABLE_DEFAULT_INFO 1

/* Same as NX_LOG_ENABLE_DEFAULT_DEBUG but for Warn Level */
#define NX_LOG_ENABLE_DEFAULT_WARN 1

/* Same as NX_LOG_ENABLE_DEFAULT_DEBUG but for Error Level.
 * Ideally, this shoudl alwasy be kept enabled */
#define NX_LOG_ENABLE_DEFAULT_ERROR 1

/******** Verbose Logging ************/
#if defined(SSS_HAVE_LOG_VERBOSE) && (SSS_HAVE_LOG_VERBOSE)
#define VERBOSE_APDU_LOGS 1
#ifdef NX_LOG_ENABLE_DEFAULT_DEBUG
#undef NX_LOG_ENABLE_DEFAULT_DEBUG
#define NX_LOG_ENABLE_DEFAULT_DEBUG 1
#endif
#endif

/******** Silent Logging ************/
#if defined(SSS_HAVE_LOG_SILENT) && (SSS_HAVE_LOG_SILENT)
#undef NX_LOG_ENABLE_DEFAULT_DEBUG
#undef NX_LOG_ENABLE_DEFAULT_INFO
#undef NX_LOG_ENABLE_DEFAULT_WARN
#undef NX_LOG_ENABLE_DEFAULT_ERROR

#define NX_LOG_ENABLE_DEFAULT_DEBUG 0
#define NX_LOG_ENABLE_DEFAULT_INFO 0
#define NX_LOG_ENABLE_DEFAULT_WARN 0
#define NX_LOG_ENABLE_DEFAULT_ERROR 0
#endif

#endif /* NX_LOG_CONFIG_H */
