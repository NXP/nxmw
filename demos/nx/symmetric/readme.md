# Symmetric AES Example

This project demonstrates Symmetric Cryptography - AES encryption and
decryption operations using an AES-128 key in the CBC mode.

Refer [**Symmetric Example**](./ex_sss_symmetric.c)

## About the Example

This example does a symmetric cryptography AES encryption and decryption operation.

It uses the following APIs and data types:

    `sss_symmetric_context_init()`
    `kAlgorithm_SSS_AES_CBC` from :cpp`sss_algorithm_t`
    `kSSS_CipherType_AES`from :cpp`sss_cipher_type_t`
    `kMode_SSS_Encrypt`from :cpp`sss_mode_t`
    `sss_cipher_one_go()`
    `kMode_SSS_Decrypt`from :cpp`sss_mode_t`
    `sss_symmetric_context_free()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

  - Project - `ex_symmetric`

The access condition of the authentication should match access condition
configuration for Cmd.CryptoRequest and Cmd.ChangeKey which can be
configured through Cmd.SetConfiguration Option 0x15.

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Running AES Symmetric Example ex_sss_symmetric.c
App   :INFO :Do Encryption
App   :INFO :icv (Len=16)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
App   :INFO :srcData (Len=16)
      48 45 4C 4C    4F 48 45 4C    4C 4F 48 45    4C 4C 4F 31
App   :INFO :Encryption successful !!!
App   :INFO :Encrypted data (Len=16)
      32 A6 04 88    C5 B3 FF 40    50 AF 56 A5    68 AE D1 05
App   :INFO :Do Decryption
App   :INFO :icv (Len=16)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
App   :INFO :Encrypted data (Len=16)
      32 A6 04 88    C5 B3 FF 40    50 AF 56 A5    68 AE D1 05
App   :INFO :Decryption successful !!!
App   :INFO :Decrypted data (Len=16)
      48 45 4C 4C    4F 48 45 4C    4C 4F 48 45    4C 4C 4F 31
App   :INFO :ex_sss_symmetric Example Success !!!...
App   :INFO :ex_sss Finished
```
