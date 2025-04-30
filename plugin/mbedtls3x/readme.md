# Introduction on Mbed TLS (3.x) ALT Implementation

Mbed TLS ALT implementation allows Mbed TLS stack use the secure
authenticator access using SSS layer. Crypto operations performed using
the secure authenticator.

Crypto operations supported -

1.  ECDSA Sign. **Refer** [**ecdsa_sign_alt**](./ecdsa_sign_alt.c)

2.  ECDSA Verify. **Refer** [**ecdsa_sign_alt**](./ecdsa_verify_alt.c)

3.  Random number generation. **Refer** [**ctr_drbg_alt**](./ctr_drbg_alt.c)

4.  AES ECB/CBC encryption/decryption.
    **Refer** [**aes_alt**](./aes_alt.c)

5.  ECDH **Refer** [**ecdh_alt**](./ecdh_alt.c)

## Example 
   **Refer** [**ex_mbedtls_3_x_alt**](../../demos/nx/mbedtls_3_x_alt/ex_mbedtls_3_x_alt.c)


>**Note:** <span style="color:blue;"> 1. For ECDSA ALT implementation, every time the control goes to ALT implementation,
    session open and close is performed. This will have all transient objects will be lost.
    To avoid the session open / close in ALT implementation,
    Use the sss_mbedtls_set_keystore_ecdsa_sign() / sss_mbedtls_set_keystore_ecdsa_verify()/
    APIs to pass the key store.</span>

>**Note:** <span style="color:blue;">2. Use Reference key to refer to the actual key in NX Secure Authenticator for ECDSA Sign Operation.
    Using nxclitool you can generate / inject a key pair in SA and create reference key for the same. **Refer** [**nxclitool_scripts**](../../demos/nx/nx_cli_tool/scripts/nxclitool_genkey_refkey.bat) for example commands.</span>

>**Note:** <span style="color:blue;">3. ECDSA Verify works only when the session authentication is Symmetric. Not with Sigma-I.</span>

>**Note:** <span style="color:blue;">4. Random number generation is offloaded to NX Secure authenticator only if the key store
    is passed using sss_mbedtls_set_keystore_rng() API. (No session open done in alt implementation)</span>

>**Note:** <span style="color:blue;">5. ECDH key derivation is offloaded to NX Secure authenticator only if the key store
    is passed using sss_mbedtls_set_keystore_ecdh() API. (No session open done in alt implementation)</span>

>**Note:** <span style="color:blue;">6. AES ECB/CBC encryption/decryption is offloaded to NX Secure authenticator only if the key store
    is passed using sss_mbedtls_set_keystore_aes() API. (No session open done in alt implementation)
    For AES ALT, the key is always set at location 0x08 (kSE_CryptoDataSrc_TB0). And AES ALT works only
    in plain authentication mode(``NXMW_Auth=None``). The access conditions can be configured
    through Cmd.SetConfiguration Option 0x15. **Refer** [**nx_tool_setconfig**](../../demos/nx/nx_tool_setconfig/readme.md)</span>

## Key Management

Mbed TLS requires a key pair, consisting of a private and a public key,
to be loaded before the cryptographic operations can be executed. This
creates a challenge when Mbed TLS is used in combination with a secure
authenticator as the private key cannot be extracted out from the Secure
authenticator.

The solution is to populate the Key data structure with only a reference
to the Private Key inside the Secure authenticator instead of the actual
Private Key. The public key as read from the Secure authenticator can
still be inserted into the key structure.

When the control comes to the ALT implementation, we check if the key is
a reference key or not. In case of reference key, the key id is
extracted and Secure authenticator is used to perform Sign operation. If
the key is not a reference key, execution will roll back to software
implementation.

## Reference Key

**Refer to** [**ec-reference-key-format**](../openssl_provider/readme.md).

## Build / Configuration of Mbed TLS ALT files

Mbed TLS library can be built with above ALT files using the below cmake
options

CMake configurations (To be applied on top of a configured host build
area):: - Select CMake options:

1.  `NXMW_HostCrypto=MBEDTLS`

2.  `NXMW_MBedTLS=3_X`

3.  `NXMW_mbedTLS_ALT=SSS`

The custom configuration file to enable required ALT operation is
present in **Refer config file for Windows** [**mbedtls_sss_alt_config**](./mbedtls_sss_alt_config.h) **Refer config file for KSDK** [**sss_ksdk_mbedtls_3x_alt_config**](../../lib/sss/port/ksdk/sss_ksdk_mbedtls_3x_alt_config.h) By default
only ECDSA Sign is enabled.

Use the below macros in the configuration file
**Refer** [**mbedtls_sss_alt_config**](./mbedtls_sss_alt_config.h) to enable / disable
required crypto operation

- MBEDTLS_ECDSA_SIGN_ALT

- MBEDTLS_ECDSA_VERIFY_ALT

- MBEDTLS_AES_ENCRYPT_ALT

- MBEDTLS_AES_DECRYPT_ALT

- MBEDTLS_ECDH_COMPUTE_SHARED_ALT

## Secure Authenticator usage with ALT files in TLS handshake

SA is used for following operations during TLS handshake.

1.  ECDSA Sign using provisioned client key.

2.  Optional - All ECDSA verify operation.

## Testing Mbed TLS ALT (Windows)

Mbed TLS client and server example can be used to test the Mbed TLS ALT
implementation.

- Project: `mbedtls_3x_client` and `mbedtls_3x_server`

    - Build client example with ALT option enabled
        `-DPTMW_mbedTLS_ALT:STRING=SSS`

    - Build server example with ALT option disabled 
        `-DPTMW_mbedTLS_ALT:STRING=None`


### Running examples -

Directory `nxmw\plugin\mbedtls3x\scripts` contains test scripts for
starting Mbed TLS server and client applications with different cipher
suites. Before executing some test scripts, the secure authenticator
must first be provisioned.

1.  Provision secure authenticator using python scripts in directory
    `nxmw\plugin\mbedtls3x\scripts`.

    Build nxclitool (Refer :ref:\_nx-cli-tool) with cmake options

    1.  `NXMW_All_Auth_Code=Enabled`

    2.  `NXMW_Auth=SYMM_Auth`

    3.  `NXMW_Secure_Tunneling=NTAG_AES128_EV2`

    4.  `NXMW_mbedTLS_ALT=none`

    To provision secure authenticator for ECC
    `create_and_provision_ecc_keys.py -auth_type symmetric -smcom vcom -port "COM3" -curve prime256v1 -waccess 0x0E`

    To see possible values of input arguments, run without any
    parameters `create_and_provision_ecc_keys.py.`

    .. note:: when running with vcom set port using
    EX_SSS_BOOT_SSS_PORT=<COM_PORT>.

2.  Starting Mbed TLS SSL client and server applications::

        python start_ssl2_server.py <ec_curve>
        python start_ssl2_client.py <ec_curve> <cipher suite>