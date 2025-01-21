/*
*
* Copyright 2022-2023 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#ifndef NX_SECURE_MSG_CONST_H_
#define NX_SECURE_MSG_CONST_H_

/* ************************************************************************** */
/* Defines                                                                    */
/* ************************************************************************** */

#define ASN_ECC_NIST_256_HEADER_LEN 26
#define ASN_ECC_BP_256_HEADER_LEN 27

#define GPCS_KEY_TYPE_AES 0x88
#define GPCS_KEY_LEN_AES 16

#define CLA_ISO7816 (0x00)         //!< ISO7816-4 defined CLA byte
#define CLA_GP_7816 (0x80)         //!< GP 7816-4 defined CLA byte
#define CLA_GP_SECURITY_BIT (0x04) //!< GP CLA Security bit

#define INS_GP_INITIALIZE_UPDATE (0x50)        //!< Global platform defined instruction
#define INS_GP_EXTERNAL_AUTHENTICATE (0x82)    //!< Global platform defined instruction
#define INS_GP_ISO_GENERAL_AUTHENTICATE (0x86) //!< Global platform defined instruction
#define INS_GP_SELECT (0xA4)                   //!< Global platform defined instruction
#define INS_GP_PUT_KEY (0xD8)                  //!< Global platform defined instruction
#define INS_GP_INTERNAL_AUTHENTICATE (0x88)    //!< Global platform defined instruction
#define INS_GP_GET_DATA (0xCA)                 //!< Global platform defined instruction
#define P1_GP_GET_DATA (0xBF)                  //!< Global platform defined instruction
#define P2_GP_GET_DATA (0x21)                  //!< Global platform defined instruction
#define P1_SIGMA_I (0x01)
#define P1_ECDSA_V3 (0x02)
#define P1_ECDSA_V4 (0x03)

#define NTAG_AES128_EV2_COMMAND_MAC_SIZE (8) // length of the MAC appended in the APDU payload (8 'MSB's)

// First byte of SIGMA-I Certificate signature data
#define SIGMA_I_SIG_DATA_PREFIX_01 0x01
#define SIGMA_I_SIG_DATA_PREFIX_02 0x02

#define BP256_NISTP256_RAW_PK_SIZE 64
#define SIGMA_I_SIG_DATA_OFFSET_PREFIX 0x00
#define SIGMA_I_SIG_DATA_OFFSET_INITIATOR_KEYSIZE 0x01
#define SIGMA_I_SIG_DATA_OFFSET_RESPONDER_KEYSIZE 0x02
#define SIGMA_I_SIG_DATA_OFFSET_HOST_EPHEM_PK (1 + 1 + 1) // TAG+Init keysize+Resp keysize
#define SIGMA_I_SIG_DATA_OFFSET_SE_EPHEM_PK \
    (1 + 1 + 1 + BP256_NISTP256_RAW_PK_SIZE) // TAG+Init keysize+Resp keysize + host ephem public key
// Prefix+Init keysize+Resp keysize + host ephem public key + device ephem public key
#define SIGMA_I_SIG_DATA_OFFSET_CMAC (1 + 1 + 1 + BP256_NISTP256_RAW_PK_SIZE + BP256_NISTP256_RAW_PK_SIZE)
#define SIGMA_I_SIG_CMAC_DATA_OFFSET_PREFIX 0x00
#define SIGMA_I_SIG_CMAC_DATA_OFFSET_HASH 0x01

#endif /*NX_SECURE_MSG_CONST_H_*/
