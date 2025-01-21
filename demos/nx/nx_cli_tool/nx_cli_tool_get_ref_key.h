/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

#define REF_KEY_LEN_MAX 256

void nxclitool_show_command_help_get_ref_key()
{
    printf("\nUSAGE: nxclitool get-ref-key [OPTIONS]\n");
    printf("\n");
    printf("OPTIONS:\n");
    printf("  -in\t\tPath to the public key in PEM format\n");
    printf("  -keyid\tECC private key ID associated with the repository\n");
    printf("  [-out]\tStores the reference key to a file on this path (optional argument)\n");
    printf("\n");
}

sss_status_t nxclitool_get_ref_key(int argc,
    const char *argv[],
    nxclitool_sss_boot_ctx_t *pCtx,
    uint32_t key_id,
    char *in_file,
    char *out_file,
    bool out_file_flag)
{
    // Holder for 32 bit key_id into four bytes
    uint8_t bytes_of_keyid[4] = {0};
    sss_status_t status       = kStatus_SSS_Fail;
    /* clang-format off */
/*
    Reference key common structure:
    -  a header of 7 bytes (Tag: 30, Length: allocated at the end)
    -  a pattern of ``0x10..00`` to fill up the data structure MSB side to the
    desired key length
    -  a 32 bit key identifier (in the example below ``0x00000002``)
    -  a 64 bit magic number (always ``0xA5A6B5B6A5A6B5B6``)
    -  a byte to describe the key class (``0x10`` for Key pair and ``0x20`` for
    Public key)
    -  a byte to describe the key index (use a reserved value ``0x00``)
    -  a tag to represent start of the public key (0xA0)
*/
    uint8_t ref_key[REF_KEY_LEN_MAX] = {
        0x30, 0x00, 0x02, 0x01, 0x01, 0x04, 0x20,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xA5, 0xA6, 0xB5, 0xB6, 0xA5, 0xA6, 0xB5, 0xB6,
        0x20,
        0x00,
        0xA0
    };
    /* clang-format on */
    size_t ref_key_len                        = 40;
    FILE *ref_fh                              = NULL;
    FILE *pub_fh                              = NULL;
    uint8_t pem_pub_key[MAX_CERT_BUF_LEN + 1] = {0};
    size_t pem_pub_key_len                    = sizeof(pem_pub_key);
    uint8_t pub_key[PUBKEY_LEN_MAX]           = {0};
    uint8_t *pk_ptr                           = NULL;
    size_t pub_key_len                        = sizeof(pub_key);
    char name[]                               = "EC PRIVATE KEY";

    // Converting 32 bit key ID into 4 bytes
    LOG_I("Using key ID as 0x%X", key_id);
    memcpy(bytes_of_keyid, &key_id, sizeof(key_id));

    ref_key[25] = bytes_of_keyid[3];
    ref_key[26] = bytes_of_keyid[2];
    ref_key[27] = bytes_of_keyid[1];
    ref_key[28] = bytes_of_keyid[0];

    pub_fh = fopen(in_file, "rb");
    if (NULL == pub_fh) {
        LOG_E("Unable to open the certificate file at path \"%s\"", in_file);
        status = kStatus_SSS_Fail;
        goto exit;
    }
    LOG_I("Using public key at \"%s\"", in_file);
    if (convert_pem_to_der(pub_fh, pem_pub_key, pem_pub_key_len, pub_key, &pub_key_len) != 0) {
        LOG_E("Unable to convert from PEM to DER");
        status = kStatus_SSS_Fail;
        if (0 != fclose(pub_fh)) {
            LOG_W("Failed to close the file handle");
        }
        goto exit;
    }
    if (0 != fclose(pub_fh)) {
        LOG_W("Failed to close the file handle");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    LOG_MAU8_I("Raw public key", pub_key, pub_key_len);

    if (pub_key_len != (size_t)(pub_key[1] + 2)) {
        LOG_E("Public key validation failed!!");
        status = kStatus_SSS_Fail;
        goto exit;
    }

    pk_ptr = &pub_key[0];
    LOG_I("Tag: 0x%X", *pk_ptr++);
    LOG_I("Length: 0x%X", *pk_ptr++);
    LOG_MAU8_I("Header", pk_ptr, 11);
    pk_ptr += 11;

    LOG_I("Tag: 0x%X", *pk_ptr);
    ENSURE_OR_GO_EXIT(ref_key_len < REF_KEY_LEN_MAX);
    ref_key[ref_key_len] = pk_ptr[1] + 2;
    ref_key_len++;
    ENSURE_OR_GO_EXIT(ref_key_len < REF_KEY_LEN_MAX);
    memcpy(&ref_key[ref_key_len], pk_ptr, pk_ptr[1] + 2);
    ref_key_len += pk_ptr[1] + 2;
    pk_ptr++;
    LOG_I("Length: 0x%X", *pk_ptr++);
    LOG_MAU8_I("Header", pk_ptr, pk_ptr[-1]);
    pk_ptr += pk_ptr[-1];

    LOG_I("Adding tag: 0xA1");
    ENSURE_OR_GO_EXIT(ref_key_len < REF_KEY_LEN_MAX);
    ref_key[ref_key_len] = 0xA1; // Tag for next header
    ref_key_len++;
    LOG_I("Adding length: 0x%X", pk_ptr[1] + 2);
    ENSURE_OR_GO_EXIT(ref_key_len < REF_KEY_LEN_MAX);
    ref_key[ref_key_len] = pk_ptr[1] + 2;
    ref_key_len++;

    LOG_MAU8_I("Adding rest of the key", pk_ptr, pk_ptr[1] + 2);
    ENSURE_OR_GO_EXIT(ref_key_len < REF_KEY_LEN_MAX);
    memcpy(&ref_key[ref_key_len], pk_ptr, pk_ptr[1] + 2);
    ref_key_len += pk_ptr[1] + 2;
    ENSURE_OR_GO_EXIT(ref_key_len >= 2);
    ref_key[1] = (uint8_t)ref_key_len - 2;

    LOG_MAU8_I("Reference key has been generated", ref_key, ref_key_len);

    if (out_file_flag) {
        ref_fh = fopen(out_file, "wb");
        if (NULL == ref_fh) {
            LOG_W("Unable to open a file to store the reference key");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        LOG_I("Storing the reference key at \"%s\"", out_file);
        if (0 != nxclitool_store_der_to_pem(ref_fh, ref_key, &ref_key_len, name, sizeof(name))) {
            status = kStatus_SSS_Fail;
            if (0 != fclose(ref_fh)) {
                LOG_E("Failed to close the file handle!");
            }
            goto exit;
        }
        if (0 != fclose(ref_fh)) {
            LOG_E("Failed to close the file handle!");
        }
    }
    else {
        LOG_W("No output file path provided. Reference key has not be saved in file system");
    }
    status = kStatus_SSS_Success;

exit:
    return status;
}