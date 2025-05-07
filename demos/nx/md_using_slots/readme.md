# Message Digest Example (Using slots in NX Secure Authenticator)

This project demonstrates a Message Digest / hashing operation using Nx
apis. Nx Secure Authenticator has the option of storing the resultant
hash in either an internal buffer (static/transient) or sending it out
over a buffer. This example how to use the Nx API to store the result in
an internal buffer.

Refer [**MD Example Using Slots**](./ex_sss_md_using_slots.c)

## About the Example

This example calculates the digest of a sample data and output data
(hash) is stored in static buffer 0 and 1. Note that, although we give
kSE_CryptoDataSrc_SB0 (i.e. static slot no. 0) as the only input to
the API, the output hash is actually stored in the buffers
kSE_CryptoDataSrc_SB0 and kSE_CryptoDataSrc_SB1. This is because
each buffer is 16 bytes in size and the SHA256 shall produce 32 bytes of
hash. Internally, the buffers are aligned in a contiguous fashion, hence
the output hash gets stored in both the buffers.

It uses the following APIs and data types:

	- `nx_CryptoRequest_SHA_Oneshot()`
	- `kSE_CryptoDataSrc_SB0`from :cpp`SE_CryptoDataSrc_t`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

	- Project -  `ex_md_using_slots`

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
App   :INFO :Digest will be written to static buffer 0 and 1
App   :INFO :ex_nx_digest Example Success !!!...
App   :INFO :ex_sss Finished
```

