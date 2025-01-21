# CMAC Example (Using slots in NX Secure Authenticator)

This project demonstrates a CMAC operation using NX APIs.

Refer [**CMAC Example**](./ex_nx_cmac_using_slots.c)

## About the Example

This project demonstrates a CMAC operation using nx apis. The data is stored in static buffer 0 (kSE_CryptoDataSrc_SB0) and output is stored in transient buffer 0 (kSE_CryptoDataSrc_TB0). This allows to use the CMAC for e.g. key derivation, with keeping the derived key in the Nx secure authenticator.

It uses the following APIs and data types:

- `nx_CryptoRequest_Write_Internal_Buffer()`
- `nx_CryptoRequest_AES_CMAC_Sign()`

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).

	- project: `ex_cmac_using_slots`

The access condition of the authentication should match access condition configuration for Cmd.CryptoRequest which can be configured through Cmd.SetConfiguration Option 0x15.

## Console output

If everything is successful, the output will be similar to:
```
ss   :INFO :Session Open Succeed
App   :INFO :Running CMAC Example (using Slots) ex_nx_cmac_using_slots.c
App   :INFO :Do CMAC
App   :INFO :input (Len=16)
      00 01 02 03    04 05 06 07    08 09 0A 0B    0C 0D 0E 0F
App   :INFO :CMAC output (Len=16)
      7B CF BB CA    7A 2E A6 8B    96 6F C5 39    9F 74 80 9E
App   :INFO :ex_nx_cmac_using_slots Example Success !!!...
App   :INFO :ex_sss Finished
```
