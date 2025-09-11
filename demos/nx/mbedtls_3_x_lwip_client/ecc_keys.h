/*
 *
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <string.h>

#if ECC_KEY_TYPE

/* Root CA Certficate */

const char tls_rootca_file[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIICIDCCAcagAwIBAgIUNrubQOQncLqgPn4TmpZKIrowu+UwCgYIKoZIzj0EAwIw\r\n"
    "ZTELMAkGA1UEBhMCQUIxCzAJBgNVBAgMAlhZMQswCQYDVQQHDAJMSDEUMBIGA1UE\r\n"
    "CgwLTlhQLURlbW8tQ0ExEjAQBgNVBAsMCURlbW8tVW5pdDESMBAGA1UEAwwJbG9j\r\n"
    "YWxob3N0MB4XDTI1MDYwMjExMTczOFoXDTMzMDEzMTExMTczOFowZTELMAkGA1UE\r\n"
    "BhMCQUIxCzAJBgNVBAgMAlhZMQswCQYDVQQHDAJMSDEUMBIGA1UECgwLTlhQLURl\r\n"
    "bW8tQ0ExEjAQBgNVBAsMCURlbW8tVW5pdDESMBAGA1UEAwwJbG9jYWxob3N0MFow\r\n"
    "FAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABBUR7m5QNKaZ5NRx9mAOsi1pReDp+Bp+\r\n"
    "lDFxyRO1TsUbUFxL579W5wcRDtkS/M6uzMfGEhuaYmU24o+gdvxJCtKjUzBRMB0G\r\n"
    "A1UdDgQWBBRt455dBZyzmumsX7XVFiGdSH0C6jAfBgNVHSMEGDAWgBRt455dBZyz\r\n"
    "mumsX7XVFiGdSH0C6jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUC\r\n"
    "IQCQ3k6Xg6ur57XRCfKpy1L3C5yq73oh/bzBl5jEcaO2CwIgXujB5qzXaepRFa/y\r\n"
    "zrsFisamHUrrumTq/RoqCbozu0s=\r\n"
    "-----END CERTIFICATE-----\r\n";
int tls_rootca_file_len = sizeof(tls_rootca_file);

#if WITH_SA
/* Read keys from SE */
const char tls_client_ref_key[] = "";
int tls_client_ref_key_len      = sizeof(tls_client_ref_key);
const char tls_client_file[]    = "";
int tls_client_file_len         = sizeof(tls_client_file);

#else

const char tls_client_ref_key[] =
    "-----BEGIN EC PRIVATE KEY-----\r\n"
    "MHgCAQEEIBAAAAAAAAAAAAAAAAAAAAAAAAAAAAKlprW2paa1tiAAoAsGCSskAwMC\r\n"
    "CAEBB6FEA0IABCIP7OpIZGoZODyRSJUyGiHj50V4mnBF+aHEccDYCF0ifJz+In5B\r\n"
    "en9yjITxUyuVnpRwwBcg8zvFAv2aWClXwU4=\r\n"
    "-----END EC PRIVATE KEY-----\r\n";

int tls_client_ref_key_len = sizeof(tls_client_ref_key);

const char tls_client_file[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIBxjCCAWwCFAdQ4ghP4m9nLaA7LqbaLrs6rDI9MAoGCCqGSM49BAMCMGUxCzAJ\r\n"
    "BgNVBAYTAkFCMQswCQYDVQQIDAJYWTELMAkGA1UEBwwCTEgxFDASBgNVBAoMC05Y\r\n"
    "UC1EZW1vLUNBMRIwEAYDVQQLDAlEZW1vLVVuaXQxEjAQBgNVBAMMCWxvY2FsaG9z\r\n"
    "dDAeFw0yNTA2MDIxMTE3MzlaFw0zMzAxMzExMTE3MzlaMGUxCzAJBgNVBAYTAkFC\r\n"
    "MQswCQYDVQQIDAJYWTELMAkGA1UEBwwCTEgxFDASBgNVBAoMC05YUC1EZW1vLUNB\r\n"
    "MRIwEAYDVQQLDAlEZW1vLVVuaXQxEjAQBgNVBAMMCWxvY2FsaG9zdDBaMBQGByqG\r\n"
    "SM49AgEGCSskAwMCCAEBBwNCAAQiD+zqSGRqGTg8kUiVMhoh4+dFeJpwRfmhxHHA\r\n"
    "2AhdInyc/iJ+QXp/coyE8VMrlZ6UcMAXIPM7xQL9mlgpV8FOMAoGCCqGSM49BAMC\r\n"
    "A0gAMEUCIQCBQNQ3kEYNM1ajHlB8Aoj823kDkAB+b4M8tHVBh+xA5wIgWW0fOlRx\r\n"
    "tBAf90SYNH/Yw2jbGgux4sPH5d6WwgjrerY=\r\n"
    "-----END CERTIFICATE-----\r\n";
int tls_client_file_len = sizeof(tls_client_file);

#endif //#if WITH_SA
#endif //#if ECC_KEY_TYPE