# HMAC Example

This project demonstrates an HMAC operation on a message using SSS APIs.

Refer [**HMAC Example**](./ex_sss_hmac.c)

## About the Example

This example does an HMAC operation on input data.

It uses the following APIs and data types:

  - `sss_mac_context_init()`
  - `kAlgorithm_SSS_HMAC_SHA256` from `sss_algorithm_t`
  - `kMode_SSS_Mac` from `sss_mode_t`
  - `sss_mac_one_go()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

  - Project - `ex_hmac`
  - The access condition of the authentication should match access condition configuration for Cmd.CryptoRequest and Cmd.ChangeKey which can be configured through Cmd.SetConfiguration Option 0x15.

## Console output

If everything is successful, the output will be similar to:

```
sss   :INFO :Session Open Succeed
App   :INFO :Running HMAC (SHA256) Example ex_sss_hmac.c
App   :INFO :Do HMAC
App   :INFO :input (Len=10)
      48 65 6C 6C    6F 57 6F 72    6C 64
App   :INFO :hmac key (Len=16)
      48 65 6C 6C    6F 48 65 6C    6C 6F 48 65    6C 6C 6F 48
App   :INFO :HMAC (SHA256) successful !!!
App   :INFO :hmac (Len=32)
      68 7A 26 95    49 67 9D 6E    FA 11 19 5E    96 CB BA C2
      6B 50 A5 09    10 8A D1 48    B5 FC A0 94    2C BD 10 21
App   :INFO :ex_sss_hmac Example Success !!!...
App   :INFO :ex_sss Finished
```
