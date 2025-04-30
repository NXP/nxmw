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

If everything is successful, the output will be similar to:
```
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Running HMAC Key Derivation Function Example ex_sss_hkdf.c
nx_mw :INFO :Do Key Derivation
nx_mw :INFO :salt (Len=32)
                AA 1A 2A E3     B2 76 15 4D     67 F9 D8 4C     B9 35 54 56
                BB 1B 2B 03     04 05 06 07     08 09 0A 0B     0C 0D 0E 0F
nx_mw :INFO :info (Len=80)
                00 01 02 03     04 05 06 07     08 09 0A 0B     0C 0D 0E 0F
                10 11 12 13     14 15 16 17     18 19 1A 1B     1C 1D 1E 1F
                20 21 22 23     24 25 26 27     28 29 2A 2B     2C 2D 2E 2F
                30 31 32 33     34 35 36 37     38 39 3A 3B     3C 3D 3E 3F
                40 41 42 43     44 45 46 47     48 49 4A 4B     4C 4D 4E 4F
nx_mw :INFO :Key Derivation successful !!!
nx_mw :INFO :hkdfOutput (Len=128)
                0A BB A2 EE     5F 25 04 CD     13 2E AF 2A     FC 60 76 5A
                DC 38 27 D4     58 7D EA 6C     FE C9 B7 0F     42 7C 66 82
                92 8C 2C A2     27 31 92 2B     36 28 23 7D     BA 3B FE 9C
                1B 08 F0 F9     19 BD 4E D0     51 90 2D 70     9A F5 35 7F
                21 80 1F EF     B4 48 98 BE     8F 2E C8 2D     75 A6 5A EB
                83 E0 C1 C0     5B EF CB 47     73 FC 81 27     03 8D 16 75
                10 43 65 67     F6 9D B8 E7     83 BA 32 6A     E0 90 E7 AE
                D5 85 80 75     68 6C 5C E7     38 4A 6D B7     4E A9 0E D2
nx_mw :INFO :ex_sss_hkdf Example Success !!!...
nx_mw :INFO :ex_sss Finished
```
