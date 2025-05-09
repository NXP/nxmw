# Mbed-TLS 3x Example

This project demonstrates ECDSA sing/verify, ECDH, RNG, ECB
encryption/decryption operation on a message using SSS API and
offloading the operations to NX SA using mbedtls alt file.
**Refer** - [**Mbed-TLS 3x Intro**](../../../plugin/mbedtls3x/readme.rst)

**Refer** - [**Mbed-TLS 3x Example**](./ex_mbedtls_3_x_alt.c)

## Prerequisites

The custom configuration file to enable required ALT operation is
present in **Refer config file for Windows** - [**mbedtls_sss_alt_config**](../../../plugin/mbedtls3x/mbedtls_sss_alt_config.h) **Refer config file for KSDK** [**sss_ksdk_mbedtls_3x_alt_config**](../../../lib/sss/port/ksdk/sss_ksdk_mbedtls_3x_alt_config.h) By
default ECDSA Sign are enabled.

Use the below macros in the config file
**Refer config file for Windows** - [**mbedtls_sss_alt_config**](../../../plugin/mbedtls3x/mbedtls_sss_alt_config.h) **Refer config file for KSDK** [**sss_ksdk_mbedtls_3x_alt_config**](../../../lib/sss/port/ksdk/sss_ksdk_mbedtls_3x_alt_config.h) to enable / disable
required crypto operation

- MBEDTLS_ECDSA_SIGN_ALT

- MBEDTLS_ECDSA_VERIFY_ALT

- MBEDTLS_AES_ENCRYPT_ALT

- MBEDTLS_AES_DECRYPT_ALT

- MBEDTLS_ECDH_COMPUTE_SHARED_ALT

## About the Example

- ex_mbedtls3x_ecdsa_sign function does the following -

    1. Injecting the actual keypair on host.
    2. Sign using SSS APIs. Mbed-TLS alt will do a software rollback and uses host for ECDSA sign.
    3. Injecting actual key in Secure Authenticator.
    4. Injecting reference key on Host.
    5. Sign using SSS APIs, Mbed-TLS alt uses NX SA for sign.

>**Note:** 
    In the default implementation, every time the control goes to ALT implementation,
    session open and close is performed. This will have all transient objects will be lost.
    To avoid the session open / close in ALT implementation,
    Use the sss_mbedtls_set_keystore_ecdsa_sign() / sss_mbedtls_set_keystore_ecdsa_verify()/
    APIs to pass the key store.


- ex_mbedtls3x_ecdsa_verify function does the following -

    1. Injecting actual key in Secure Authenticator.
    2. Sign using SSS APIs. Mbed-TLS ALT will do software rollback and will use host for ECDSA Sign.
    3. Injecting public key on Host.
    4. Verify using SSS APIs. Mbed-TLS ALT will use NX SA for verify.

>**Note:** 
    ECDSA Verify works only when the session authentication is Symmetric. Not with Sigma-I.


- ex_mbedtls3x_rng_gen function does the following -

    1. Generate random numbers using NX SA.

>**Note:** 
    Random number generation is offloaded to NX Secure authenticator only if the key store
    is passed using sss_mbedtls_set_keystore_rng() API.


- ex_mbedtls3x_ecdh function does the following -

    1. Create a transient key in secure authenticator.
    2. Create and injecting the ref key on host.
    3. Injecting the public key on host.
    4. Derive ECDH using SSS APIs. Mbed-TLS alt use NX SA for ECDH.

>**Note:** 
    ECDH key derivation is offloaded to NX Secure authenticator only if the key store
    is passed using sss_mbedtls_set_keystore_ecdh() API.


- ex_mbedtls3x_ebc , ex_mbedtls3x_cbc, ex_mbedtls3x_cmac functions does
the following -

- ex_mbedtls3x_ebc
  1.  Inject aes key on host.
  2.  AES ECB encryption using SSS APIs. Mbed-TLS alt will do a software
      rollback since key store is not set.
  3.  AES ECB decryption using SSS APIs. Mbed-TLS alt will do a software
      rollback since key store is not set.
  4.  Set key store using sss_mbedtls_set_keystore_aes API.
  5.  AES ECB encryption using SSS APIs, Mbed-TLS alt use SE for ECB
      encryption.
  6.  AES ECB decryption using SSS APIs, Mbed-TLS alt use SE for ECB
      decryption.
- ex_mbedtls3x_cbc
  1.  Inject aes key on host.
  2.  AES CBC encryption using SSS APIs. Mbed-TLS alt will do a software
      rollback since key store is not set.
  3.  AES CBC decryption using SSS APIs. Mbed-TLS alt will do a software
      rollback since key store is not set.
  4.  Set key store using sss_mbedtls_set_keystore_aes API.
  5.  AES CBC encryption using SSS APIs, Mbed-TLS alt use SE for CBC
      encryption.
  6.  AES CBC decryption using SSS APIs, Mbed-TLS alt use SE for CBC
      decryption.
- ex_mbedtls3x_cmac
  1.  Inject aes key on host.
  2.  AES CMAC sign using SSS APIs. Mbed-TLS alt will do a software
      rollback since key store is not set.
  3.  AES CMAC verify using SSS APIs. Mbed-TLS alt will do a software
      rollback since key store is not set.
  4.  Set key store using sss_mbedtls_set_keystore_aes API.
  5.  AES CMAC sign using SSS APIs, Mbed-TLS alt use SE for CMAC sign.
  6.  AES CMAC verify using SSS APIs, Mbed-TLS alt use SE for CMAC
      verify.

>**Note:** 
    AES ECB/CBC encryption/decryption is offloaded to NX Secure authenticator only if the key store
    is passed using sss_mbedtls_set_keystore_aes() API.
    Only plain authentication mode (``NXMW_Auth=None``) is supported.
    set access condition plain mode for Cmd.CryptoRequest and which can be configured
    through Cmd.SetConfiguration Option 0x15 (Refer [**nx_tool_setconfig**](../nx_tool_setconfig/readme.md)).
    Example:

          nx_tool_setconfig.exe -cryptoCM plain -cryptoAC 0xE COM10


>**Note:** 
    To run ecdsa, ecdh and rng alt example on plain commMode or none authentication.
    set access condition plain mode for Cmd.CryptoRequest, Cmd.Managekeypair and which can be configured
    through Cmd.SetConfiguration Option 0x15 and 0x12 (Refer [**nx_tool_setconfig**](../nx_tool_setconfig/readme.md)).
    Example:

          nx_tool_setconfig.exe -cryptoCM plain -cryptoAC 0xE COM10
          nx_tool_setconfig.exe -keypairCM plain -keypairAC 0xE COM10


## Building the Example

- Project: `ex_mbedtls_3_x_alt`

1.  `NXMW_HostCytpo=MBEDTLS`

2.  `NXMW_MBedTLS=3_X`

3.  `NXMW_mbedTLS_ALT=SSS`

Other options should be selected according to IC configuration.