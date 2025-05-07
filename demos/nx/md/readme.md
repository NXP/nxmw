# Message Digest Example

This project demonstrates a Message Digest / hashing operation using SSS APIs.

Refer [**MD Example**](./ex_sss_md.c)

## About the Example

This example calculates the digest of a sample data and will compare with expected value.

It uses the following APIs and data types:
    `sss_digest_context_init()`
    `kAlgorithm_SSS_SHA256`from `sss_algorithm_t`
    `kMode_SSS_Digest` from `sss_mode_t`
    `sss_digest_one_go()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

	- Project - `ex_md`

The access condition of the authentication should match access condition
configuration for Cmd.CryptoRequest which can be configured through
Cmd.SetConfiguration Option 0x15.

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Running Message Digest Example ex_sss_md.c
App   :INFO :Do Digest
App   :INFO :input (Len=10)
      48 65 6C 6C    6F 57 6F 72    6C 64
App   :INFO :Message Digest successful !!!
App   :INFO :digest (Len=32)
      87 2E 4E 50    CE 99 90 D8    B0 41 33 0C    47 C9 DD D1
      1B EC 6B 50    3A E9 38 6A    99 DA 85 84    E9 BB 12 C4
App   :INFO :ex_sss_digest Example Success !!!...
App   :INFO :ex_sss Finished
```

