/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#include <nx_apdu.h>
#include <fsl_sss_nx_auth_types.h>
#include <fsl_sss_nx_types.h>

/* clang-format off */
#define CERT_REPO_SIZE 0xC00
#define EX_CERT_REPO_DEVICE_LEAF_PRIVATE_KEY \
    {   0x89, 0xA1, 0x5F, 0x15, 0xFB, 0x93, 0x06, 0x03,     \
        0x83, 0x87, 0x6B, 0x5F, 0xA3, 0x5A, 0xB3, 0x3F,     \
        0x0F, 0x22, 0xB4, 0x9F, 0xD2, 0x8F, 0xF8, 0x27,     \
        0xB3, 0x5F, 0xC9, 0x6E, 0xA2, 0x93, 0x13, 0xE7      \
    }

// Root certificate subject name(9a): 30.06, A0.30.02,31,30,A0.30.30.A0,02,30,30,30,30
#define EX_ROOT_CERT_SUBJECT_NAME_PKCS7_ASN1_LIST \
    {   0x30, 0x81, 0x06, 0x82, 0xA0, 0x81, 0x30, 0x81,        \
        0x02, 0x82, 0x31, 0x82, 0x30, 0x82, 0xA0, 0x81,        \
        0x30, 0x81, 0x30, 0x81, 0xA0, 0x82, 0x02, 0x82,        \
        0x30, 0x82, 0x30, 0x82, 0x30, 0x82, 0x30, 0x83         \
    }

// Root certificate subject name: 30.30.a0,02,30,30,30,30 (9a)
#define EX_ROOT_CERT_SUBJECT_NAME_X509_ASN1_LIST \
    {   0x30, 0x81, 0x30, 0x81, 0xa0, 0x82, 0x02, 0x82,         \
        0x30, 0x82, 0x30, 0x82, 0x30, 0x82, 0x30, 0x83          \
    }

// Root cert pk(95): 30 . 06 , a0 . 30 . 02 , 31 ,30 ,a0 . 30 . 30 . a0 , 02 , 30 , 30 , 30 , 30 , 30 . 30 , 03
#define EX_ROOT_CERT_PUBKEY_PKCS7_ASN1_LIST \
    {   0x30, 0x81, 0x06, 0x82, 0xA0, 0x81, 0x30, 0x81,         \
        0x02, 0x82, 0x31, 0x82, 0x30, 0x82, 0xA0, 0x81,         \
        0x30, 0x81, 0x30, 0x81, 0xA0, 0x82, 0x02, 0x82,         \
        0x30, 0x82, 0x30, 0x82, 0x30, 0x82, 0x30, 0x82,         \
        0x30, 0x81, 0x30, 0x82, 0x03, 0x83                      \
    }

// Root cert pk(95) 30 . 30 . a0, 02 , 30 , 30 , 30 , 30 , 30 . 30 , 03
#define EX_ROOT_CERT_PUBKEY_X509_ASN1_LIST \
    {   0x30, 0x81, 0x30, 0x81, 0xa0, 0x82, 0x02, 0x82,         \
        0x30, 0x82, 0x30, 0x82, 0x30, 0x82, 0x30, 0x82,         \
        0x30, 0x81, 0x30, 0x82, 0x03, 0x83                      \
    }

#define EX_HOST_CA_ROOT_KEY_ACCESS_RIGHT                                                           \
    ((1 << Nx_AC_Bitmap_13_Shift) | (1 << Nx_AC_Bitmap_12_Shift) | (1 << Nx_AC_Bitmap_11_Shift) |  \
        (1 << Nx_AC_Bitmap_10_Shift) | (1 << Nx_AC_Bitmap_9_Shift) | (1 << Nx_AC_Bitmap_8_Shift) | \
        (1 << Nx_AC_Bitmap_7_Shift) | (1 << Nx_AC_Bitmap_6_Shift) | (1 << Nx_AC_Bitmap_5_Shift) |  \
        (1 << Nx_AC_Bitmap_4_Shift) | (1 << Nx_AC_Bitmap_3_Shift) | (1 << Nx_AC_Bitmap_2_Shift) |  \
        (1 << Nx_AC_Bitmap_1_Shift) | (1 << Nx_AC_Bitmap_0_Shift))

#define EX_SSS_SIGMA_I_NISTP256_SE_LEAF_KEYPAIR \
    {                                           \
        0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x37, 0xE0,   \
        0x1B, 0xA2, 0x81, 0xCE, 0x32, 0x00, 0x26, 0xA6, 0x36,   \
        0x5C, 0xFF, 0x39, 0xF9, 0x1D, 0xED, 0x2F, 0x47, 0xAC,   \
        0x88, 0xFA, 0x53, 0x8A, 0x88, 0xD4, 0x73, 0xFF, 0xC8,   \
        0xB6, 0xD3, 0x31, 0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86,   \
        0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0xA1, 0x44, 0x03,   \
        0x42, 0x00, 0x04, 0xAD, 0x5D, 0x30, 0xA9, 0x8F, 0xBA,   \
        0x4A, 0xD1, 0x95, 0x47, 0xD5, 0xD3, 0xA2, 0xAE, 0x50,   \
        0x90, 0x4D, 0x41, 0x15, 0x92, 0x87, 0x60, 0x45, 0x06,   \
        0x47, 0xBC, 0xEE, 0x30, 0x06, 0xEA, 0xD1, 0xA3, 0x88,   \
        0x00, 0x3C, 0xAC, 0x9D, 0x7F, 0x22, 0xF6, 0x4E, 0x97,   \
        0x60, 0x0A, 0xBE, 0x69, 0x43, 0x50, 0x22, 0xAD, 0x40,   \
        0xF6, 0x3C, 0xEE, 0x3D, 0x08, 0xC1, 0x88, 0x6B, 0xCD,   \
        0xEF, 0x97, 0xF0, 0xDE                                  \
    }
/* clang-format on */

sss_status_t nxclitool_get_cert_repo_command_parameters(int argc,
    const char *argv[],
    uint32_t *repo_id,
    uint32_t *key_id,
    NX_CERTIFICATE_LEVEL_t *cert_level,
    Nx_CommMode_t *write_comm_mode,
    Nx_AccessCondition_t *write_access_cond,
    Nx_CommMode_t *read_comm_mode,
    Nx_AccessCondition_t *read_access_cond,
    Nx_CommMode_t *known_comm_mode,
    char *file_name,
    bool *file_flag);
sss_status_t nxclitool_get_ca_root_command_parameters(int argc,
    const char *argv[],
    uint32_t *key_id,
    Nx_ECCurve_t *curve_type,
    char *file_name,
    bool *file_flag,
    bool *is_pkcs7);
sss_status_t nxclitool_crt_repo_create(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx);
sss_status_t nxclitool_crt_repo_activate(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx);
sss_status_t nxclitool_crt_repo_reset(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx);
sss_status_t nxclitool_crt_repo_load_root_ca_key(int argc,
    const char *argv[],
    nxclitool_sss_boot_ctx_t *pCtx,
    bool is_pkcs7,
    uint8_t key_id,
    Nx_ECCurve_t curve_type,
    char file_name[]);
sss_status_t nxclitool_crt_repo_read_metadata(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx);
sss_status_t nxclitool_crt_repo_read_cert(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx);

void nxclitool_show_command_help_crt_repo_create_cmd()
{
    printf("\nUSAGE: nxclitool certrepo-create [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -keyid:\t\t\tECC private key ID associated with the repository\n");
    printf("  -repoid:\t\t\tCertificate Repository ID\n");
    printf(
        "  -wcomm, -rcomm, -kcomm:\tWrite, Read, Known Communication Modes respectively, required to write to/read "
        "from the repository. Accepted values:\n");
    printf("\t\t\t\t  full\n");
    printf("\t\t\t\t  mac\n");
    printf("\t\t\t\t  na\n");
    printf("\t\t\t\t  plain\n");
    printf(
        "  -waccess, -raccess:\t\tWrite, Read Access Rights respectively, required to write to/read from the "
        "repository. Accepted values:\n");
    printf("\t\t\t\t  0x00 to 0x0C\tAuth required\n");
    printf("\t\t\t\t  0x0D\t\tFree over I2C\n");
    printf("\t\t\t\t  0x0E\t\tFree Access\n");
    printf("\t\t\t\t  0x0F\t\tNo Access\n");
    printf("\n");
}

void nxclitool_show_command_help_crt_repo_loadkey_cmd()
{
    printf("\nUSAGE: nxclitool certrepo-load-key [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -certtype\tCertificate wrapping. Accepted values:\n");
    printf("\t\t  pkcs7\n");
    printf("\t\t  x509\n");
    printf("  -curve\tECC Curve type for the key. Accepted values:\n");
    printf("\t\t  brainpoolP256r1\n");
    printf("\t\t  prime256v1\n");
    printf("\t\t  NA\n");
    printf("  -in\t\tPath to the certificate/key\n");
    printf("  -keyid\tKey ID for setting Root CA Key\n");
    printf("  -keytype\tType of key to be loaded in the repository. Accepted values:\n");
    printf("\t\t  leaf\n");
    printf("\t\t  rootca\n");
}

void nxclitool_show_command_help_crt_repo_load_cert_cmd()
{
    printf("\nUSAGE: nxclitool certrepo-load-cert [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -certlevel\tLevel of the certificate. Accepted values:\n");
    printf("\t\t  leaf\n");
    printf("\t\t  p1\n");
    printf("\t\t  p2\n");
    printf("\t\t  root\n");
    printf("  -in\t\tPath to the certificate/key\n");
    printf("  -kcomm\tKnown Communication Mode, required to write to/read from the repository. Accepted values:\n");
    printf("\t\t  full\n");
    printf("\t\t  mac\n");
    printf("\t\t  na\n");
    printf("\t\t  plain\n");
    printf("  -repoid\tCertificate Repository ID\n");
    printf("\n");
}

void nxclitool_show_command_help_crt_repo_load_mapping_cmd()
{
    printf("\nUSAGE: nxclitool certrepo-load-mapping [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -certlevel\tLevel of the certificate. Accepted values:\n");
    printf("\t\t  leaf\n");
    printf("\t\t  p1\n");
    printf("\t\t  p2\n");
    printf("\t\t  root\n");
    printf("  -in\t\tPath to the certificate/key\n");
    printf("  -repoid\tCertificate Repository ID\n");
    printf("\n");
}

void nxclitool_show_command_help_crt_repo_activate_cmd()
{
    printf("\nUSAGE: nxclitool certrepo-activate [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -kcomm\tKnown Communication Mode, required to write to/read from the repository. Accepted values:\n");
    printf("\t\t  full\n");
    printf("\t\t  mac\n");
    printf("\t\t  na\n");
    printf("\t\t  plain\n");
    printf("  -repoid\tCertificate Repository ID\n");
    printf("\n");
}

void nxclitool_show_command_help_crt_repo_reset_cmd()
{
    printf("\nUSAGE: nxclitool certrepo-reset [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -repoid\t\t\tCertificate Repository ID in hex format\n");
    printf(
        "  -wcomm, -rcomm, -kcomm:\tWrite, Read, Known Communication Modes respectively, required to write to/read "
        "from the repository. Accepted values:\n");
    printf("\t\t\t\t  full\n");
    printf("\t\t\t\t  mac\n");
    printf("\t\t\t\t  na\n");
    printf("\t\t\t\t  plain\n");
    printf(
        "  -waccess, -raccess:\t\tWrite, Read Access Rights respectively, required to write to/read from the "
        "repository. Accepted values:\n");
    printf("\t\t\t\t  0x00 to 0x0C\tAuth required\n");
    printf("\t\t\t\t  0x0D\t\tFree over I2C\n");
    printf("\t\t\t\t  0x0E\t\tFree Access\n");
    printf("\t\t\t\t  0x0F\t\tNo Access\n");
    printf("\n");
}

void nxclitool_show_command_help_crt_repo_read_crt_cmd()
{
    printf("\nUSAGE: nxclitool certrepo-read-cert [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -certlevel\tLevel of the certificate. Accepted values:\n");
    printf("\t\t  leaf\n");
    printf("\t\t  p1\n");
    printf("\t\t  p2\n");
    printf("\t\t  root\n");
    printf("  -kcomm\tKnown Communication Mode for the repository. Accepted values:\n");
    printf("\t\t  full\n");
    printf("\t\t  mac\n");
    printf("\t\t  na\n");
    printf("\t\t  plain\n");
    printf("  -out\t\tOutput file path\n");
    printf("  -repoid\tCertificate Repository ID\n");
    printf("\n");
}

void nxclitool_show_command_help_crt_repo_read_metadata_cmd()
{
    printf("\nUSAGE: nxclitool certrepo-read-metadata [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -repoid\tCertificate Repository ID in hex format\n");
    printf("\n");
}

/**
 *  The function will create tagged certificate from input certificate.
 *
 * @param tagged_cert[out] Pointer to tagged certificate.
 * @param tagged_cert_len[out] Pointer to tagged certificate length.
 * @param certBuf[in] Pointer to input certificate.
 * @param certBufLen[in] Input certificate length.
 *
 * @returns Status of the operation
 * @retval #kStatus_SSS_Success The operation has completed successfully.
 * @retval #kStatus_SSS_Fail The operation has failed.
 */
static sss_status_t nxclitool_add_uncompressed_cert_tag(
    uint8_t *tagged_cert, size_t *tagged_cert_len, uint8_t *certBuf, size_t certBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    int tlvRet          = 1;
    uint8_t *pCert      = NULL;

    ENSURE_OR_GO_CLEANUP(tagged_cert != NULL);
    ENSURE_OR_GO_CLEANUP(tagged_cert_len != NULL);
    ENSURE_OR_GO_CLEANUP(certBuf != NULL);

    tagged_cert[0]   = NX_TAG_CERT_DATA;
    pCert            = &tagged_cert[1];
    *tagged_cert_len = 0;
    tlvRet           = TLVSET_u8buf(
        "cert", &pCert, tagged_cert_len, NX_TAG_UNCOMPRESSED_CERT, certBuf, certBufLen, MAX_CERT_BUF_LEN - 1);
    ENSURE_OR_GO_CLEANUP(tlvRet == 0);
    ENSURE_OR_GO_CLEANUP(*tagged_cert_len < UINT_MAX);
    *tagged_cert_len = *tagged_cert_len + 1;
    status           = kStatus_SSS_Success;

cleanup:
    if (kStatus_SSS_Success != status) {
        LOG_E("Add certificate data tag failed.");
    }

    return status;
}

bool nxclitool_parse_for_cert_type(
    const uint8_t *input, size_t inLen, uint8_t *identifier, size_t identifierLen, size_t identifierIndex)
{
    size_t i = 0;

    if ((SIZE_MAX - identifierIndex < identifierLen) || (identifierIndex + identifierLen > inLen)) {
        return FALSE;
    }

    while (identifierLen) {
        if (input[i + identifierIndex] != identifier[i]) {
            return FALSE;
        }
        i++;
        identifierLen--;
    }
    return TRUE;
}

// Validates the NXP specific TLV and returns the offset from where actual certificate starts after NXP specific TLV
sss_status_t nxclitool_parse_and_validate_nx_tag(uint8_t *buffer, size_t *buf_len, size_t *offset)
{
    sss_status_t status = kStatus_SSS_Fail;
    uint8_t tag         = 0;
    size_t len          = 0;

    *offset = 0;
    LOG_I("Parsing the fetched certificate");
    if (*buf_len == 0) {
        goto exit;
    }

    tag = buffer[0];
    (*buf_len)--;
    if (*buf_len == 0) {
        goto exit;
    }
    buffer++;
    (*offset)++;
    switch (tag) {
    case 0x7F:
        tag = buffer[0];
        (*buf_len)--;
        if (*buf_len == 0) {
            goto exit;
        }
        buffer++;
        (*offset)++;
        switch (tag) {
        case 0x21:
            // 0x7F21
            LOG_I("\tCertificate type: Uncompressed certificate");
            break;
        case 0x22:
            // 0x7F22
            LOG_I("\tCertificate type: Compressed certificate");
            break;
        default:
            LOG_E("Invalid tag found");
            goto exit;
        }
        break;
    case 0x80:
        LOG_I("\tCertificate type: Certificate request (Leaf, level = 0)");
        break;
    case 0x81:
        LOG_I("\tCertificate type: Certificate request (Parent, level = 0)");
        break;
    case 0x82:
        LOG_I("\tCertificate type: Certificate request (Parent, level = 0)");
        break;
    case 0x83:
        LOG_I("\tCertificate type: AES key size options");
        break;
    case 0x84:
        LOG_I("\tCertificate type: Certificate Hash");
        break;
    case 0x85:
        LOG_I("\tCertificate type: ECC Signature");
        break;
    case 0x86:
        LOG_I("\tCertificate type: Ephemeral ECDH public key, plaintext, uncompressed format");
        break;
    case 0x87:
        LOG_I("\tCertificate type: Encrypted payload");
        break;
    default:
        LOG_E("Invalid tag found");
        goto exit;
    }

    tag = buffer[0];
    (*buf_len)--;
    if (*buf_len == 0) {
        goto exit;
    }
    buffer++;
    (*offset)++;
    if (tag <= 0x80) {
        ENSURE_OR_GO_EXIT(tag == *buf_len);
    }
    else {
        switch (tag) {
        case 0x81:
            tag = buffer[0];
            (*buf_len)--;
            if (*buf_len == 0) {
                LOG_E("Certificate length is zero");
                goto exit;
            }
            buffer++;
            (*offset)++;
            ENSURE_OR_GO_EXIT(tag == *buf_len);
            break;
        case 0x82:
            tag = buffer[0];
            (*buf_len)--;
            if (*buf_len == 0) {
                goto exit;
            }
            buffer++;
            (*offset)++;
            len = tag;
            len <<= 8;
            tag = buffer[0];
            (*buf_len)--;
            if (*buf_len == 0) {
                LOG_E("Certificate length is zero");
                goto exit;
            }
            buffer++;
            (*offset)++;
            len += tag;
            ENSURE_OR_GO_EXIT(len == *buf_len);
            break;
        default:
            LOG_E("Invalid tag found");
            goto exit;
        }
    }
    LOG_I("\tCertificate length: %u", *buf_len);
    status = kStatus_SSS_Success;

exit:
    return status;
}

static sss_status_t nxclitool_validate_certificate_length(size_t certLen)
{
    sss_status_t status   = kStatus_SSS_Fail;
    size_t size_of_length = 0;

    // Boundary check for certificate size
    size_of_length = (certLen <= 0x7f ? 1 : (certLen <= 0xFF ? 2 : 3));

    ENSURE_OR_GO_CLEANUP((UINT_MAX - 2 - size_of_length) > certLen);
    // 7F 21 [Len] [Cert]
    ENSURE_OR_GO_CLEANUP((2 + size_of_length + certLen) <= NX_MAX_CERTIFICATE_SIZE);

    status = kStatus_SSS_Success;

cleanup:
    if (kStatus_SSS_Success != status) {
        LOG_E("Too large certificate.");
    }

    return status;
}

static sss_status_t nxclitool_sss_nx_get_cert_value_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t i            = 0;
    int ret             = 0;
    uint8_t fieldTag = 0, qualifierTag = 0;
    uint8_t *pCert = NULL, *certEnd = NULL;
    size_t len = 0;

    if ((certBuf == NULL) || (asn1TagList == NULL) || (dataBuf == NULL) || (dataBufLen == NULL)) {
        goto exit;
    }

    pCert   = certBuf;
    len     = certBufLen;
    certEnd = pCert + len;

    for (i = 0; ((i <= (SIZE_MAX - 2)) && ((i + 1) < asn1TagListLen)); i = i + 2) {
        fieldTag     = asn1TagList[i];
        qualifierTag = asn1TagList[i + 1];

        if (fieldTag != 0x00) {
            if ((ret = sss_util_asn1_get_tag(&pCert, certEnd, &len, fieldTag)) != 0) {
                LOG_E("Parse certificate tag 0x%X error", fieldTag);
                goto exit;
            }
        }
        else {
            // 0x00 tag, in fact, is padding for BIT STRING.
            pCert++;
            len = 0;
        }

        if (qualifierTag == NX_Qualifier_Nested) {
            ;
        }
        else if (qualifierTag == NX_Qualifier_Follow) {
            pCert += len;
        }
        else if (qualifierTag == NX_Qualifier_End) {
            // pCert point to value field, len is the value field length.
            break;
        }
        else {
            LOG_E("Invalid Qualifier Tag 0x%x error", qualifierTag);
            goto exit;
        }
    }

    if (qualifierTag != NX_Qualifier_End) {
        LOG_E("No Qualifier End Tag found");
        goto exit;
    }

    // pCert point to value field, len is the value field length.

    *dataBuf    = pCert;
    *dataBufLen = len;

    status = kStatus_SSS_Success;

exit:
    return status;
}

static sss_status_t nxclitool_sss_nx_get_cert_tlv_field(uint8_t *certBuf,
    size_t certBufLen,
    uint8_t *asn1TagList,
    size_t asn1TagListLen,
    uint8_t **dataBuf,
    size_t *dataBufLen)
{
    sss_status_t status = kStatus_SSS_Fail;
    size_t i            = 0;
    int ret             = 0;
    uint8_t fieldTag = 0, qualifierTag = 0;
    uint8_t *pCert = NULL, *certEnd = NULL, *pTag = NULL;
    size_t len = 0;

    if ((certBuf == NULL) || (asn1TagList == NULL) || (dataBuf == NULL) || (dataBufLen == NULL)) {
        goto exit;
    }

    pCert   = certBuf;
    len     = certBufLen;
    certEnd = pCert + len;

    for (i = 0; ((i <= (SIZE_MAX - 2)) && ((i + 1) < asn1TagListLen)); i = i + 2) {
        fieldTag     = asn1TagList[i];
        qualifierTag = asn1TagList[i + 1];

        pTag = pCert;

        if (fieldTag != 0x00) {
            if ((ret = sss_util_asn1_get_tag(&pCert, certEnd, &len, fieldTag)) != 0) {
                LOG_E("Parse certificate tag 0x%x error", fieldTag);
                goto exit;
            }
        }
        else {
            // 0x00 tag, in fact, is padding for BIT STRING.
            pCert++;
            len = 0;
        }

        if (qualifierTag == NX_Qualifier_Nested) {
            ;
        }
        else if (qualifierTag == NX_Qualifier_Follow) {
            pCert += len;
        }
        else if (qualifierTag == NX_Qualifier_End) {
            // pCert point to value field, len is the value field length.
            break;
        }
        else {
            LOG_E("Invalid Qualifier Tag 0x%x error", qualifierTag);
            goto exit;
        }
    }

    if (qualifierTag != NX_Qualifier_End) {
        LOG_E("No Qualifier End Tag found");
        goto exit;
    }

    // pTag is start of tag field
    *dataBuf = pTag;
    ENSURE_OR_GO_EXIT((UINT_MAX - (size_t)(pCert - pTag)) >= len);
    *dataBufLen = pCert - pTag + len;

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nxclitool_provision_load_host_root_CA_pubkey(nxclitool_sss_boot_ctx_t *pCtx,
    Nx_ECCurve_t curve_type,
    uint8_t hostRootPubKeyId,
    uint16_t accessRight,
    uint8_t *certBuf,
    size_t certLen,
    uint8_t *pkASN1TagList,
    size_t pkASN1TagListLen,
    uint8_t *subjectNameTagList,
    size_t subjectNameTagListLen)
{
    sss_status_t status          = kStatus_SSS_Fail;
    sss_nx_session_t *pSession   = NULL;
    sss_cipher_type_t cipherType = {0};
    sss_object_t keyObject       = {0};
    sss_policy_u rootKeyPolicy   = {
        .type   = KPolicy_UpdateCARootKey,
        .policy = {.updCARootKey =
                       {
                           .acBitmap        = accessRight,
                           .writeCommMode   = Nx_CommMode_FULL,
                           .writeAccessCond = Nx_AccessCondition_Auth_Required_0x0,
                           .userCommMode    = Nx_CommMode_NA,
                       }},
    };
    sss_policy_t root_key_policy = {.nPolicies = 1, .policies = {&rootKeyPolicy}};
    uint8_t *pubKey = NULL, *issuerName = NULL;
    size_t pubKeyLen = 0, issuerNameLen = 0;

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    ENSURE_OR_GO_EXIT((pkASN1TagList != NULL) && (subjectNameTagList != NULL));
    ENSURE_OR_GO_EXIT((curve_type == Nx_ECCurve_Brainpool256) || (curve_type == Nx_ECCurve_NIST_P256));

    pSession = (sss_nx_session_t *)&pCtx->session;

    // Get Subject Name from certificate.
    status = nxclitool_sss_nx_get_cert_tlv_field(
        certBuf, certLen, subjectNameTagList, subjectNameTagListLen, &issuerName, &issuerNameLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Get public key from certificate.
    status =
        nxclitool_sss_nx_get_cert_value_field(certBuf, certLen, pkASN1TagList, pkASN1TagListLen, &pubKey, &pubKeyLen);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    // Remove 00 pad at the header
    pubKey++;
    if (pubKeyLen <= 0) {
        status = kStatus_SSS_Fail;
        goto exit;
    }
    pubKeyLen--;

    if (issuerNameLen > UINT8_MAX) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    status = kStatus_SSS_Fail;

    // Update issuer name in policy
    memset(rootKeyPolicy.policy.updCARootKey.issuer, 0, sizeof(rootKeyPolicy.policy.updCARootKey.issuer));
    memcpy(rootKeyPolicy.policy.updCARootKey.issuer, issuerName, issuerNameLen);
    rootKeyPolicy.policy.updCARootKey.issuerLen = issuerNameLen;

    // Update write access condition in policy
    if (pSession->s_ctx.authType == knx_AuthType_SYMM_AUTH) {
        if (pSession->s_ctx.ctx.pdynSymmAuthCtx != NULL) {
            rootKeyPolicy.policy.updCARootKey.writeAccessCond = pSession->s_ctx.ctx.pdynSymmAuthCtx->keyNo;
        }
        else {
            LOG_E("Invalid symm auth context !!!");
            goto exit;
        }
    }

    if (curve_type == Nx_ECCurve_Brainpool256) {
        cipherType = kSSS_CipherType_CARootKeys_BRAINPOOL;
    }
    else {
        cipherType = kSSS_CipherType_CARootKeys_NIST_P;
    }

    status = sss_key_object_init(&keyObject, &pCtx->ks);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_allocate_handle(
        &keyObject, hostRootPubKeyId, kSSS_KeyPart_Public, cipherType, 256 / 8, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status =
        sss_key_store_set_key(&pCtx->ks, &keyObject, pubKey, pubKeyLen, 256, &root_key_policy, sizeof(root_key_policy));
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = kStatus_SSS_Success;

exit:
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }
    return status;
}

sss_status_t nxclitool_crt_repo_create(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    smStatus_t sm_status                   = SM_NOT_OK;
    sss_status_t status                    = kStatus_SSS_Fail;
    sss_nx_session_t *pSession             = NULL;
    uint32_t repo_id                       = 0x03;
    uint32_t key_id                        = 0x00;
    Nx_CommMode_t write_comm_mode          = Nx_CommMode_FULL;
    Nx_CommMode_t read_comm_mode           = Nx_CommMode_FULL;
    Nx_CommMode_t known_comm_mode          = Nx_CommMode_NA;
    Nx_AccessCondition_t write_access_cond = Nx_AccessCondition_Auth_Required_0x0;
    Nx_AccessCondition_t read_access_cond  = Nx_AccessCondition_Auth_Required_0x0;

    ENSURE_OR_RETURN_ON_ERROR(NULL != pCtx, kStatus_SSS_Fail);
    pSession = (sss_nx_session_t *)&pCtx->session;

    if (nxclitool_fetch_parameters(argc,
            argv,
            2,
            NULL,
            &repo_id,
            &key_id,
            NULL,
            NULL,
            NULL,
            &write_comm_mode,
            &write_access_cond,
            &read_comm_mode,
            &read_access_cond,
            &known_comm_mode,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL)) {
        LOG_E("Failed to fetch parameters for Create Certificate Repository command. Check usage below");
        nxclitool_show_command_help_crt_repo_create_cmd();
        status = kStatus_SSS_Fail;
        return status;
    }

    LOG_I("Using repo ID: 0x%X", repo_id);
    LOG_I("Using key ID: 0x%X", key_id);

    switch (write_comm_mode) {
    case 0x00:
        LOG_I("Using write communication mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using write communication mode as MAC");
        break;
    case 0x03:
        LOG_I("Using write communication mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using write communication mode as NA");
        break;
    default:
        LOG_E("Invalid write communication mode");
        break;
    }

    switch (write_access_cond) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
        LOG_I("Using write access condition as AUTH REQUIRED 0x%X", write_access_cond);
        break;
    case 0x0D:
        LOG_I("Using write access condition as FREE OVER I2C");
        break;
    case 0x0E:
        LOG_I("Using write access condition as FREE ACCESS");
        break;
    case 0x0F:
        LOG_I("Using write access condition as NO ACCESS");
        break;
    default:
        LOG_E("Invalid write access condition");
        break;
    }

    switch (read_comm_mode) {
    case 0x00:
        LOG_I("Using read communication mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using read communication mode as MAC");
        break;
    case 0x03:
        LOG_I("Using read communication mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using read communication mode as NA");
        break;
    default:
        LOG_E("Invalid read communication mode");
        break;
    }

    switch (read_access_cond) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
        LOG_I("Using read access condition as AUTH REQUIRED 0x%X", read_access_cond);
        break;
    case 0x0D:
        LOG_I("Using read access condition as FREE OVER I2C");
        break;
    case 0x0E:
        LOG_I("Using read access condition as FREE ACCESS");
        break;
    case 0x0F:
        LOG_I("Using read access condition as NO ACCESS");
        break;
    default:
        LOG_E("Invalid read access condition");
        break;
    }

    switch (known_comm_mode) {
    case 0x00:
        LOG_I("Using Known Communication Mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using Known Communication Mode as MAC");
        break;
    case 0x03:
        LOG_I("Using Known Communication Mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using Known Communication Mode as NA");
        break;
    default:
        LOG_E("Invalid Known Communication Mode");
        break;
    }

    sm_status = nx_ManageCertRepo_CreateCertRepo(&((sss_nx_session_t *)pSession)->s_ctx,
        repo_id,
        key_id,
        CERT_REPO_SIZE,
        write_comm_mode,
        write_access_cond,
        read_comm_mode,
        read_access_cond,
        known_comm_mode);
    if (sm_status != SM_OK) {
        if (sm_status == SM_ERR_FILE_DUPLICATE) {
            LOG_I("Certificate repo already exist");
            status = kStatus_SSS_Success;
            return status;
        }
        else {
            LOG_E("Create Cert repo Failed !!");
            status = kStatus_SSS_Fail;
            return status;
        }
    }
    LOG_I("Certificate repo has been created at repo ID: 0x%X", repo_id);
    status = kStatus_SSS_Success;
    return status;
}

sss_status_t nxclitool_crt_repo_load_cert_and_mapping(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status                   = kStatus_SSS_Fail;
    smStatus_t sm_status                  = SM_NOT_OK;
    uint32_t repo_id                      = 0x03;
    NX_CERTIFICATE_LEVEL_t cert_level     = NX_CERTIFICATE_LEVEL_LEAF;
    Nx_CommMode_t known_comm_mode         = Nx_CommMode_NA;
    uint8_t *buffer[MAX_CERT_BUF_LEN + 1] = {0};
    size_t buffer_len                     = 0;
    char file_name[MAX_FILE_PATH_LEN]     = {0};
    uint8_t tagged_cert[MAX_CERT_BUF_LEN] = {0};
    size_t tagged_cert_len                = 0;
    sss_nx_session_t *pSession            = (sss_nx_session_t *)&pCtx->session;

    if (nxclitool_fetch_parameters(argc,
            argv,
            2,
            NULL,
            &repo_id,
            NULL,
            NULL,
            &cert_level,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &known_comm_mode,
            NULL,
            file_name,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL)) {
        LOG_E("Failed to fetch parameters for Load command. Check usage below");
        if (0 == strcmp(argv[1], "certrepo-load-cert")) {
            nxclitool_show_command_help_crt_repo_load_cert_cmd();
        }
        else {
            nxclitool_show_command_help_crt_repo_load_mapping_cmd();
        }
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    LOG_I("Using repo ID: 0x%X", repo_id);

    switch (cert_level) {
    case 0x00:
        LOG_I("Using Certificate Level as LEAF");
        break;
    case 0x01:
        LOG_I("Using Certificate Level as P1");
        break;
    case 0x02:
        LOG_I("Using Certificate Level as P2");
        break;
    case 0x03:
        LOG_I("Using Certificate Level as REPO META DATA");
        break;
    default:
        LOG_E("Invalid Certificate Level");
        break;
    }

    switch (known_comm_mode) {
    case 0x00:
        LOG_I("Using Known Communication Mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using Known Communication Mode as MAC");
        break;
    case 0x03:
        LOG_I("Using Known Communication Mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using Known Communication Mode as NA");
        break;
    default:
        LOG_E("Invalid Known Communication Mode");
        break;
    }

    LOG_I("Using certificate at path \"%s\"", file_name);

    FILE *fh = fopen(file_name, "rb");
    if (NULL == fh) {
        LOG_E("Unable to open the certificate file at path \"%s\"", file_name);
        status = kStatus_SSS_Fail;
        goto cleanup;
    }
    buffer_len = fread(buffer, sizeof(char), MAX_CERT_BUF_LEN, fh);
    if (0 != fclose(fh)) {
        LOG_W("Failed to close the file handle");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    if (0 == strcmp(argv[1], "certrepo-load-mapping")) {
        status    = kStatus_SSS_Fail;
        sm_status = nx_ManageCertRepo_LoadCertMapping(
            &pSession->s_ctx, repo_id, cert_level, (uint8_t *)buffer, (uint16_t)buffer_len, known_comm_mode);
        ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
        LOG_I("Load device certificate mapping Successful !!!");
    }
    else if (0 == strcmp(argv[1], "certrepo-load-cert")) {
        status = nxclitool_validate_certificate_length(buffer_len);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status = nxclitool_add_uncompressed_cert_tag(tagged_cert, &tagged_cert_len, (uint8_t *)buffer, buffer_len);
        ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

        status    = kStatus_SSS_Fail;
        sm_status = nx_ManageCertRepo_LoadCert(
            &pSession->s_ctx, repo_id, cert_level, tagged_cert, (uint16_t)tagged_cert_len, known_comm_mode);
        ENSURE_OR_GO_CLEANUP(sm_status == SM_OK);
        LOG_I("Load device certificate Successful !!!");
    }
    status = kStatus_SSS_Success;

cleanup:
    return status;
}

sss_status_t nxclitool_crt_repo_load_root_ca_key(int argc,
    const char *argv[],
    nxclitool_sss_boot_ctx_t *pCtx,
    bool is_pkcs7,
    uint8_t key_id,
    Nx_ECCurve_t curve_type,
    char file_name[])
{
    sss_status_t status                    = kStatus_SSS_Fail;
    uint8_t cert_buf[MAX_CERT_BUF_LEN + 1] = {0};
    size_t cert_len                        = sizeof(cert_buf);
    FILE *fp                               = NULL;

    uint8_t *subjectNameTagList       = NULL;
    size_t subjectNameTagListLen      = 0;
    uint8_t subjectNamePKCS7TagList[] = EX_ROOT_CERT_SUBJECT_NAME_PKCS7_ASN1_LIST;
    size_t subjectNamePKCS7TagListLen = sizeof(subjectNamePKCS7TagList);
    uint8_t subjectNameX509TagList[]  = EX_ROOT_CERT_SUBJECT_NAME_X509_ASN1_LIST;
    size_t subjectNameX509TagListLen  = sizeof(subjectNameX509TagList);

    uint8_t *pkASN1TagList   = NULL;
    size_t pkASN1TagListLen  = 0;
    uint8_t pkPKCS7TagList[] = EX_ROOT_CERT_PUBKEY_PKCS7_ASN1_LIST;
    size_t pkPKCS7TagListLen = sizeof(pkPKCS7TagList);
    uint8_t pkX509TagList[]  = EX_ROOT_CERT_PUBKEY_X509_ASN1_LIST;
    size_t pkX509TagListLen  = sizeof(pkX509TagList);
    uint16_t acBitmap        = EX_HOST_CA_ROOT_KEY_ACCESS_RIGHT;

    ENSURE_OR_GO_EXIT(pCtx != NULL);

    if ((fp = fopen(file_name, "rb")) != NULL) {
        cert_len = fread(cert_buf, sizeof(char), MAX_CERT_BUF_LEN, fp);

        if ((cert_len == 0) || ferror(fp)) { /* fread failed */
            LOG_E("Error reading certificate/key from path \"%s\"", file_name);
            if (0 != fclose(fp)) {
                LOG_W("Failed to close the file handle");
            }
            goto exit;
        }

        if (0 != fclose(fp)) {
            LOG_W("Failed to close the file handle");
            goto exit;
        }
        LOG_I("Using certificate/key at path \"%s\"", file_name);
    }
    else {
        LOG_E("Unable to open the certificate/key file at path \"%s\"", file_name);
        cert_len = 0;
        goto exit;
    }

    if (is_pkcs7 == true) {
        // X.509 Certificate wrapped in PKCS#7.
        subjectNameTagList    = subjectNamePKCS7TagList;
        subjectNameTagListLen = subjectNamePKCS7TagListLen;

        pkASN1TagList    = pkPKCS7TagList;
        pkASN1TagListLen = pkPKCS7TagListLen;
    }
    else {
        // X.509 Certificate.
        subjectNameTagList    = subjectNameX509TagList;
        subjectNameTagListLen = subjectNameX509TagListLen;

        pkASN1TagList    = pkX509TagList;
        pkASN1TagListLen = pkX509TagListLen;
    }

    status = nxclitool_provision_load_host_root_CA_pubkey(pCtx,
        curve_type,
        key_id,
        acBitmap,
        cert_buf,
        cert_len,
        pkASN1TagList,
        pkASN1TagListLen,
        subjectNameTagList,
        subjectNameTagListLen);

    if (status != kStatus_SSS_Success) {
        goto exit;
    }
    LOG_I("Root CA Certificate/Key has been loaded at key ID 0x%X", key_id);

exit:
    return status;
}

sss_status_t nxclitool_provision_import_se_leaf_private_key(nxclitool_sss_boot_ctx_t *pCtx,
    uint8_t seLeafCertKeyId,
    Nx_ECCurve_t seCertCurveType,
    uint8_t *seLeafPKBuf,
    size_t seLeafPKBufLen)
{
    sss_status_t status                = kStatus_SSS_Fail;
    const sss_policy_u eccKeyGenPolicy = {.type = KPolicy_GenECKey,
        .policy                                 = {.genEcKey = {
                       .freezeKUCLimit        = 0,
                       .cardUnilateralEnabled = 0,
                       .sdmEnabled            = 0,
                       .sigmaiEnabled         = 1,
                       .eccSignEnabled        = 0,
                       .ecdhEnabled           = 0,
                       .writeCommMode         = kCommMode_FULL,
                       .writeAccessCond       = Nx_AccessCondition_Auth_Required_0x0,
                       .kucLimit              = 0,
                       .userCommMode          = Nx_CommMode_NA,
                   }}};
    sss_policy_t ec_key_policy         = {.nPolicies = 1, .policies = {&eccKeyGenPolicy}};
    sss_object_t keyObject             = {0};
    sss_cipher_type_t cipherType       = kSSS_CipherType_NONE;

    ENSURE_OR_GO_EXIT(pCtx != NULL);
    ENSURE_OR_GO_EXIT(seLeafPKBuf != NULL);

    ENSURE_OR_GO_EXIT((seCertCurveType == Nx_ECCurve_Brainpool256) || (seCertCurveType == Nx_ECCurve_NIST_P256));

    if (seCertCurveType == Nx_ECCurve_Brainpool256) {
        cipherType = kSSS_CipherType_EC_BRAINPOOL;
    }
    else {
        cipherType = kSSS_CipherType_EC_NIST_P;
    }

    // status = sss_key_store_context_init(&pCtx->ks, &pCtx->session);
    // ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = sss_key_object_init(&keyObject, &pCtx->ks);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
    status = kStatus_SSS_Fail;

    status = sss_key_object_allocate_handle(
        &keyObject, seLeafCertKeyId, kSSS_KeyPart_Private, cipherType, 256 / 8, kKeyObject_Mode_Persistent);
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);
    status = kStatus_SSS_Fail;

    status = sss_key_store_set_key(
        &pCtx->ks, &keyObject, seLeafPKBuf, seLeafPKBufLen, 256, &ec_key_policy, sizeof(ec_key_policy));
    ENSURE_OR_GO_EXIT(kStatus_SSS_Success == status);

    status = kStatus_SSS_Success;

exit:
    if (keyObject.keyStore != NULL) {
        sss_key_object_free(&keyObject);
    }
    return status;
}

sss_status_t nxclitool_crt_repo_load_leaf_key(int argc,
    const char *argv[],
    nxclitool_sss_boot_ctx_t *pCtx,
    bool is_pkcs7,
    uint8_t key_id,
    Nx_ECCurve_t curve_type,
    char file_name[])
{
    sss_status_t status      = kStatus_SSS_Fail;
    uint8_t key_buf[256 + 1] = {0};
    size_t key_buf_len       = sizeof(key_buf);
    uint8_t priv_key_buf[32] = {0};
    size_t priv_key_buf_len  = sizeof(priv_key_buf);
    FILE *fp                 = NULL;
    size_t file_size         = 0;

    if ((fp = fopen(file_name, "rb")) != NULL) {
        file_size = fread(key_buf, sizeof(char), 256, fp);

        if ((file_size == 0) || ferror(fp)) { /* fread failed */
            LOG_E("Error reading certificate/key from path \"%s\"", file_name);
            if (0 != fclose(fp)) {
                LOG_W("Failed to close the file handle");
            }
            goto exit;
        }
        else { /* fread success */
            key_buf_len = file_size;
        }

        if (0 != fclose(fp)) {
            LOG_W("Failed to close the file handle");
            goto exit;
        }
        LOG_I("Using certificate/key at path \"%s\"", file_name);
    }
    else {
        LOG_E("Unable to open the certificate/key file at path \"%s\"", file_name);
        key_buf_len = 0;
        goto exit;
    }

    status = nxclitool_provision_parse_keypair_get_private_key(key_buf, key_buf_len, priv_key_buf, &priv_key_buf_len);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    status = nxclitool_provision_import_se_leaf_private_key(pCtx, key_id, curve_type, priv_key_buf, priv_key_buf_len);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);
    LOG_I("Leaf key has been successfully loaded at key ID 0x%X", key_id);

exit:
    return status;
}

sss_status_t nxclitool_crt_repo_load_key(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    sss_status_t status               = kStatus_SSS_Fail;
    bool is_pkcs7                     = false;
    uint32_t key_id                   = 0x00;
    uint8_t key_id_8bit               = 0x00;
    Nx_ECCurve_t curve_type           = Nx_ECCurve_NA; // BP-256 or NIST-P 256
    NXCLITOOL_KEY_TYPE_t key_type     = NXCLITOOL_KEY_TYPE_LEAF;
    char file_name[MAX_FILE_PATH_LEN] = {0};

    if (nxclitool_fetch_parameters(argc,
            argv,
            2,
            NULL,
            NULL,
            &key_id,
            &curve_type,
            NULL,
            &is_pkcs7,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &key_type,
            file_name,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL)) {
        LOG_E("Failed to fetch parameters for Load key command. Check usage below");
        nxclitool_show_command_help_crt_repo_loadkey_cmd();
        status = kStatus_SSS_Fail;
        goto cleanup;
    }

    if (key_id > UINT8_MAX) {
        LOG_E("Key ID is invalid for this operation");
        status = kStatus_SSS_Fail;
        goto cleanup;
    }
    key_id_8bit = (uint8_t)key_id;

    switch (key_type) {
    case NXCLITOOL_KEY_TYPE_LEAF:
        status = nxclitool_crt_repo_load_leaf_key(argc, argv, pCtx, is_pkcs7, key_id_8bit, curve_type, file_name);
        break;
    case NXCLITOOL_KEY_TYPE_ROOT_CA:
        status = nxclitool_crt_repo_load_root_ca_key(argc, argv, pCtx, is_pkcs7, key_id_8bit, curve_type, file_name);
        break;
    }

cleanup:
    return status;
}

sss_status_t nxclitool_crt_repo_activate(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    smStatus_t sm_status          = SM_NOT_OK;
    sss_status_t status           = kStatus_SSS_Fail;
    sss_nx_session_t *pSession    = NULL;
    uint32_t repo_id              = 0;
    Nx_CommMode_t known_comm_mode = Nx_CommMode_NA;

    ENSURE_OR_RETURN_ON_ERROR(NULL != pCtx, kStatus_SSS_Fail);
    pSession = (sss_nx_session_t *)&pCtx->session;

    if (nxclitool_fetch_parameters(argc,
            argv,
            2,
            NULL,
            &repo_id,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &known_comm_mode,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL)) {
        LOG_E("Failed to fetch parameters for Manage Certificate Repository command. Check usage below");
        nxclitool_show_command_help_crt_repo_activate_cmd();
        status = kStatus_SSS_Fail;
        return status;
    }

    LOG_I("Using repo ID: 0x%X", repo_id);
    switch (known_comm_mode) {
    case 0x00:
        LOG_I("Using Known Communication Mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using Known Communication Mode as MAC");
        break;
    case 0x03:
        LOG_I("Using Known Communication Mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using Known Communication Mode as NA");
        break;
    default:
        LOG_E("Invalid Known Communication Mode");
        break;
    }

    sm_status = nx_ManageCertRepo_ActivateRepo(&pSession->s_ctx, repo_id, known_comm_mode);
    if (sm_status == SM_OK) {
        LOG_I("Certificate repo at repo ID 0x%X has been activated", repo_id);
    }
    else {
        LOG_E("Certificate repo activation failed for repo ID 0x%X", repo_id);
        status = kStatus_SSS_Fail;
        return status;
    }
    status = kStatus_SSS_Success;
    return status;
}

sss_status_t nxclitool_crt_repo_read_cert(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    smStatus_t sm_status              = SM_NOT_OK;
    sss_status_t status               = kStatus_SSS_Fail;
    uint32_t repo_id                  = 0x00;
    NX_CERTIFICATE_LEVEL_t cert_level = NX_CERTIFICATE_LEVEL_LEAF;
    Nx_CommMode_t known_comm_mode     = Nx_CommMode_NA;
    uint8_t buffer[MAX_CERT_BUF_LEN]  = {0};
    uint8_t *pbuffer                  = buffer;
    size_t buffer_len                 = sizeof(buffer);
    size_t offset = 0; // Certificate offset from where actual certificate starts (after the NXP specific TLV)
    char file_path[MAX_FILE_PATH_LEN]   = {0};
    bool file_flag                      = 0;
    sss_nx_session_t *pSession          = (sss_nx_session_t *)&pCtx->session;
    uint8_t pkcs7SignedDataIdentifier[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
    size_t identifierIndex              = 4;
    char name[20]                       = {0};
    size_t nameLen                      = 0;
    bool isPkcs7                        = FALSE;

    if (nxclitool_fetch_parameters(argc,
            argv,
            2,
            NULL,
            &repo_id,
            NULL,
            NULL,
            &cert_level,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            &known_comm_mode,
            NULL,
            NULL,
            file_path,
            &file_flag,
            NULL,
            NULL,
            NULL)) {
        LOG_E("Failed to fetch parameters for read certificate command. Check usage below");
        nxclitool_show_command_help_crt_repo_read_crt_cmd();
        status = kStatus_SSS_Fail;
        goto exit;
    }

    switch (known_comm_mode) {
    case 0x00:
        LOG_I("Using Known Communication Mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using Known Communication Mode as MAC");
        break;
    case 0x03:
        LOG_I("Using Known Communication Mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using Known Communication Mode as NA");
        break;
    default:
        LOG_E("Invalid Known Communication Mode");
        break;
    }

    switch (cert_level) {
    case 0x00:
        LOG_I("Fetching LEAF level certificate from repository ID 0x%X", repo_id);
        break;
    case 0x01:
        LOG_I("Fetching P1 level certificate from repository ID 0x%X", repo_id);
        break;
    case 0x02:
        LOG_I("Fetching P2 level certificate from repository ID 0x%X", repo_id);
        break;
    case 0x03:
        LOG_I("Fetching ROOT level certificate from repository ID 0x%X", repo_id);
        break;
    default:
        LOG_E("Invalid Certificate Level");
        break;
    }

    sm_status = nx_ReadCertRepo_Cert(&pSession->s_ctx, repo_id, cert_level, buffer, &buffer_len, known_comm_mode);
    if (sm_status != SM_OK) {
        LOG_E("Failed to fetch certificate from repository at ID 0x%X", repo_id);
        status = kStatus_SSS_Fail;
        goto exit;
    }

    status = nxclitool_parse_and_validate_nx_tag(buffer, &buffer_len, &offset);
    ENSURE_OR_GO_EXIT(status == kStatus_SSS_Success);

    pbuffer = buffer + offset;
    LOG_MAU8_I("Fetched certificate (DER)", pbuffer, buffer_len);

    // Parse the certificate for X509 or PKCS7
    isPkcs7 = nxclitool_parse_for_cert_type(
        pbuffer, buffer_len, pkcs7SignedDataIdentifier, sizeof(pkcs7SignedDataIdentifier), identifierIndex);
    if (isPkcs7) {
        strcpy(name, "PKCS7");
        nameLen = 6;
        LOG_I("Certificate Type: PKCS7");
    }
    else {
        strcpy(name, "CERTIFICATE");
        nameLen = 12;
        LOG_I("Certificate Type: X509");
    }

    if (file_flag) {
        FILE *fh = fopen(file_path, "wb");
        if (0 != nxclitool_store_der_to_pem(fh, pbuffer, &buffer_len, name, nameLen)) {
            LOG_E("Could not store certificate to file!!");
            if (0 != fclose(fh)) {
                LOG_E("Failed to close the file handle!");
            }
            goto exit;
        }
        else {
            LOG_I("Storing the fetched certificate at \"%s\"", file_path);
        }
        if (0 != fclose(fh)) {
            LOG_W("Failed to close the file handle");
            status = kStatus_SSS_Fail;
            goto exit;
        }
    }
    else {
        LOG_W("No file path provided. Certificate will not be saved in file system");
    }
    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nxclitool_crt_repo_read_metadata(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    smStatus_t sm_status          = SM_NOT_OK;
    sss_status_t status           = kStatus_SSS_Fail;
    uint32_t repo_id              = 0x00;
    uint8_t key_id                = 0x00;
    uint16_t repo_size            = 0;
    Nx_CommMode_t write_comm_mode = Nx_CommMode_NA;
    Nx_CommMode_t read_comm_mode  = Nx_CommMode_NA;
    uint8_t write_access_cond     = Nx_AccessCondition_No_Access;
    uint8_t read_access_cond      = Nx_AccessCondition_No_Access;

    sss_nx_session_t *pSession = (sss_nx_session_t *)&pCtx->session;

    if (nxclitool_fetch_parameters(argc,
            argv,
            2,
            NULL,
            &repo_id,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL)) {
        LOG_E("Failed to fetch parameters for Reset Certificate Repository command. Check usage below");
        nxclitool_show_command_help_crt_repo_read_metadata_cmd();
        status = kStatus_SSS_Fail;
        goto exit;
    }

    LOG_I("Fetching metadata from repository ID 0x%X", repo_id);

    sm_status = nx_ReadCertRepo_Metadata(&pSession->s_ctx,
        repo_id,
        &key_id,
        &repo_size,
        &write_comm_mode,
        &write_access_cond,
        &read_comm_mode,
        &read_access_cond);
    if (sm_status != SM_OK) {
        LOG_E("Failed to fetch repository metadata at ID 0x%X", repo_id);
        status = kStatus_SSS_Fail;
        goto exit;
    }
    LOG_I("Repository meta data fetched successfully");
    LOG_I("Repository ID: 0x%X", repo_id);
    LOG_I("Private key ID: 0x%X", key_id);

    switch (write_comm_mode) {
    case 0x00:
        LOG_I("Write communication mode: PLAIN");
        break;
    case 0x01:
        LOG_I("Write communication mode: MAC");
        break;
    case 0x03:
        LOG_I("Write communication mode: FULL");
        break;
    case 0x7F:
        LOG_I("Write communication mode: NA");
        break;
    default:
        LOG_E("Invalid write communication mode");
        break;
    }

    switch (write_access_cond) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
        LOG_I("Write access condition: AUTH REQUIRED 0x%X", write_access_cond);
        break;
    case 0x0D:
        LOG_I("Write access condition: FREE OVER I2C");
        break;
    case 0x0E:
        LOG_I("Write access condition: FREE ACCESS");
        break;
    case 0x0F:
        LOG_I("Write access condition: NO ACCESS");
        break;
    default:
        LOG_E("Invalid write access condition");
        break;
    }

    switch (read_comm_mode) {
    case 0x00:
        LOG_I("Read communication mode: PLAIN");
        break;
    case 0x01:
        LOG_I("Read communication mode: MAC");
        break;
    case 0x03:
        LOG_I("Read communication mode: FULL");
        break;
    case 0x7F:
        LOG_I("Read communication mode: NA");
        break;
    default:
        LOG_E("Invalid read communication mode");
        break;
    }

    switch (read_access_cond) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
        LOG_I("Read access condition: AUTH REQUIRED 0x%X", read_access_cond);
        break;
    case 0x0D:
        LOG_I("Read access condition: FREE OVER I2C");
        break;
    case 0x0E:
        LOG_I("Read access condition: FREE ACCESS");
        break;
    case 0x0F:
        LOG_I("Read access condition: NO ACCESS");
        break;
    default:
        LOG_E("Invalid read access condition");
        break;
    }

    status = kStatus_SSS_Success;

exit:
    return status;
}

sss_status_t nxclitool_crt_repo_reset(int argc, const char *argv[], nxclitool_sss_boot_ctx_t *pCtx)
{
    smStatus_t sm_status                   = SM_NOT_OK;
    sss_status_t status                    = kStatus_SSS_Fail;
    sss_nx_session_t *pSession             = NULL;
    uint32_t repo_id                       = 0x03;
    Nx_CommMode_t write_comm_mode          = Nx_CommMode_Plain;
    Nx_CommMode_t read_comm_mode           = Nx_CommMode_Plain;
    Nx_CommMode_t known_comm_mode          = Nx_CommMode_NA;
    Nx_AccessCondition_t write_access_cond = Nx_AccessCondition_Auth_Required_0x0;
    Nx_AccessCondition_t read_access_cond  = Nx_AccessCondition_Auth_Required_0x0;

    ENSURE_OR_RETURN_ON_ERROR(NULL != pCtx, kStatus_SSS_Fail);
    pSession = (sss_nx_session_t *)&pCtx->session;

    if (nxclitool_fetch_parameters(argc,
            argv,
            2,
            NULL,
            &repo_id,
            NULL,
            NULL,
            NULL,
            NULL,
            &write_comm_mode,
            &write_access_cond,
            &read_comm_mode,
            &read_access_cond,
            &known_comm_mode,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL)) {
        LOG_E("Failed to fetch parameters for Reset Certificate Repository command. Check usage below");
        nxclitool_show_command_help_crt_repo_reset_cmd();
        status = kStatus_SSS_Fail;
        return status;
    }

    LOG_I("Using repo ID: 0x%X", repo_id);

    switch (write_comm_mode) {
    case 0x00:
        LOG_I("Using write communication mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using write communication mode as MAC");
        break;
    case 0x03:
        LOG_I("Using write communication mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using write communication mode as NA");
        break;
    default:
        LOG_E("Invalid write communication mode");
        break;
    }

    switch (write_access_cond) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
        LOG_I("Using write access condition as AUTH REQUIRED 0x%X", write_access_cond);
        break;
    case 0x0D:
        LOG_I("Using write access condition as FREE OVER I2C");
        break;
    case 0x0E:
        LOG_I("Using write access condition as FREE ACCESS");
        break;
    case 0x0F:
        LOG_I("Using write access condition as NO ACCESS");
        break;
    default:
        LOG_E("Invalid write access condition");
        break;
    }

    switch (read_comm_mode) {
    case 0x00:
        LOG_I("Using read communication mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using read communication mode as MAC");
        break;
    case 0x03:
        LOG_I("Using read communication mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using read communication mode as NA");
        break;
    default:
        LOG_E("Invalid read communication mode");
        break;
    }

    switch (read_access_cond) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03:
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B:
    case 0x0C:
        LOG_I("Using read access condition as AUTH REQUIRED 0x%X", read_access_cond);
        break;
    case 0x0D:
        LOG_I("Using read access condition as FREE OVER I2C");
        break;
    case 0x0E:
        LOG_I("Using read access condition as FREE ACCESS");
        break;
    case 0x0F:
        LOG_I("Using read access condition as NO ACCESS");
        break;
    default:
        LOG_E("Invalid read access condition");
        break;
    }

    switch (known_comm_mode) {
    case 0x00:
        LOG_I("Using Known Communication Mode as PLAIN");
        break;
    case 0x01:
        LOG_I("Using Known Communication Mode as MAC");
        break;
    case 0x03:
        LOG_I("Using Known Communication Mode as FULL");
        break;
    case 0x7F:
        LOG_I("Using Known Communication Mode as NA");
        break;
    default:
        LOG_E("Invalid Known Communication Mode");
        break;
    }

    sm_status = nx_ManageCertRepo_ResetRepo(&pSession->s_ctx,
        repo_id,
        write_comm_mode,
        write_access_cond,
        read_comm_mode,
        read_access_cond,
        known_comm_mode);
    if (sm_status != SM_OK) {
        LOG_E("Reset Certificate Repo Failed !!");
        status = kStatus_SSS_Fail;
        return status;
    }
    LOG_I("Certificate Repo has been reset at repo ID: 0x%X", repo_id);
    status = kStatus_SSS_Success;
    return status;
}