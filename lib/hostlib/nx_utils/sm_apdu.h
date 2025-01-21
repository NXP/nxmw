/*
 *
 * Copyright 2016,2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * @par Description
 * This file defines the API of the APDU parser for AX host library.
 * @par History
 * 1.0   31-mar-2014 : Initial version
 *
 */

#ifndef _SM_APDU_H_
#define _SM_APDU_H_

#define MAX_APDU_BUF_LENGTH             (256 + 1024)  // This value has not been optimized for TGT_A71CH (256+64)
#define MAX_EXT_APDU_BUF_LENGTH         (32769) // extended APDU Max supported Len is 0x7FFF + 2 bytes status code


#define APDU_HEADER_LENGTH                (5)
#define APDU_EXTENDED_HEADER_LENGTH       (7)
#define EXT_CASE4_APDU_OVERHEAD           (9)
#define RSP_APDU_STATUS_OVERHEAD          (2)
#define APDU_STD_MAX_DATA               (255)

#define SW_WRONG_LENGTH                     (0x6700) //!< ISO7816-4 defined status word: Wrong Length of data
#define SW_SECURE_MESSAGING_NOT_SUPPORTED   (0x6882) //!< ISO7816-4 defined status word
#define SW_SECURITY_STATUS_NOT_SATISFIED    (0x6982) //!< ISO7816-4 defined status word
#define SW_DATA_INVALID                     (0x6984) //!< ISO7816-4 defined status word
#define SW_CONDITIONS_NOT_SATISFIED         (0x6985) //!< ISO7816-4 defined status word: Conditions of use not satisfied, e.g. a command is not allowed, the provided identifier is not applicable or the index is out of range.
#define SW_COMMAND_NOT_ALLOWED              (0x6986) //!< ISO7816-4 defined status word
#define SW_WRONG_DATA                       (0x6A80) //!< ISO7816-4 defined status word: Wrong data, e.g. the command does not have the right parameters or a parameter is not correct (size, structure).
#define SW_FILE_NOT_FOUND                   (0x6A82) //!< ISO7816-4 defined status word
#define SW_INCORRECT_P1P2                   (0x6A86) //!< ISO7816-4 defined status word: Incorrect P1-P2 parameters
#define SW_INS_NOT_SUPPORTED                (0x6D00) //!< ISO7816-4 defined status word: INS byte not supported
#define SW_CLA_NOT_SUPPORTED                (0x6E00) //!< ISO7816-4 defined status word: CLA byte not supported
#define SW_NO_ERROR                         (0x9000) //!< ISO7816-4 defined status word

#define USE_STANDARD_APDU_LEN 0 //!< Create a standard length APDU.
#define USE_EXTENDED_APDU_LEN 1 //!< Create an extended length APDU.
#define SESSION_ID_LEN 4

#endif //_SM_APDU_H_
