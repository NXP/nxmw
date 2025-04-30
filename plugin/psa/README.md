# PSA (Platform Security Architecture)

The Platform Security Architecture (PSA) by ARM is a holistic set of
threat models, security analyses, hardware and firmware architecture
specifications, and an open source firmware reference implementation.

For details on PSA specification, refer to [ARMmbed PSA
Specification](https://armmbed.github.io/mbed-crypto/html/index.html).

## PSA SE Driver Interface

The SE Driver interface allows the user to register Secure Authenticator
drivers for various cryptographic operations. It is not necessary that
one driver should offer all cryptographic functionalities, we can
register up to 4 drivers which may offer different functionalities.

## PSA APIs in NX Middleware (supported with MbedTLS 3.X)

The PSA APIs for Secure authenticator are implemented in -
plugin/psa/\*.c.

To include the PSA plugin files in mbedTLS 3.x build enable PSA in
mbedTLS_ALT cmake option (`mbedTLS_ALT=PSA`),

The following PSA features / APIs are supported in NX middleare using
mbedTLS 3.x

1.  Nist256 and Brainpool256 Generate Key / (API - `psa_generate_key`)
2.  ECDSA Sign (Nist256 and Brainpool256) / (API - `psa_sign_hash`)
3.  AES Key import / (API - `psa_import_key`)
4.  AEAD Encrypt - one shot / (API - `psa_aead_encrypt`)
5.  AEAD Decrypt - one shot / (API - `psa_aead_decrypt`)
6.  HMAC - One shot / (API - `psa_mac_compute`)
7.  HMAC Verify - One shot / (API - `psa_mac_verify`)

## Building PSA Example

To test the above PSA APIs, refer the PSA example
(plugin/psa/psa_example/psa_example.c). Use the below cmake options to
build the example,

- Project: `psa_example`
- `Host=lpcxpresso55s69`
- `HostCrypto=MBEDTLS`
- `MBedTLS=3_X`
- `mbedTLS_ALT=PSA`