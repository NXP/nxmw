# RNG Example

This project demonstrates random number generation using SSS APIs.

Refer [**Random Number Generation Example**](./ex_sss_rng.c)

## About the Example

This example generates a random number of given length.

It uses the following APIs:
    `sss_rng_context_init()`
    `sss_rng_get_random()`
    `sss_rng_context_free()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

	- Project - `ex_rng`

The access condition of the authentication should match access condition
configuration for Cmd.CryptoRequest which can be configured through
Cmd.SetConfiguration Option 0x15.

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Running Get Random Data Example ex_sss_rng.c
App   :INFO :Get Random Data successful !!!
App   :INFO :Random (Len=32)
      1C 40 F9 B2    68 C1 2B CC    04 50 AD 18    F9 D4 A5 B9
      A1 57 32 DF    00 CA 52 96    A7 C1 0B FC    03 8C D4 6C
App   :INFO :ex_sss_rng Example Success !!!...
App   :INFO :ex_sss Finished
```

