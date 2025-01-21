# HKDF Example

This project demonstrates an HMAC Key derivation operation based on info and salt using SSS APIs.

Refer [**HKDF Example**](./ex_sss_hkdf.c)

## About the Example

This example does an HMAC Key derivation operation based on the info and salt.

It uses the following APIs and data types:

    `sss_derive_key_context_init()`
    `kAlgorithm_SSS_HMAC_SHA256` from :cpp`sss_algorithm_t`
    `kMode_SSS_HKDF_ExtractExpand` from :cpp`sss_mode_t`
    `kSSS_CipherType_AES`from :cpp`sss_cipher_type_t`
    `sss_derive_key_one_go()`

```
NOTE:

In the provided example, the derived key is output to the host. For
actual product deployment, the security implications of doing this need
to be assessed. Alternatively the derived key can be kept within the Nx
Transient or Static Buffers, similarly as shown in the ECDH example
```

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
	- Project - `ex_hkdf`

The access condition of the authentication should match access condition
configuration for Cmd.CryptoRequest and Cmd.ChangeKey which can be
configured through Cmd.SetConfiguration Option 0x15.

## Console output

```
```
