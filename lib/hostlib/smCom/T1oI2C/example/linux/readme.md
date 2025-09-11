# T1oI2C example

This project is used to demonstrate the usage of T1oI2C APIs. The
example will send a command to get available memory from Secure
Authenticator.

## Prerequisites

- Build Nx middleware stack.

## About the Example

This project gets available memory from Secure Authenticator using
T1oI2C APIs.

It uses the following API:

    `phNxpEse_open()`{.interpreted-text role="func"}
    `phNxpEse_init()`{.interpreted-text role="func"}
    `phNxpEse_Transceive()`{.interpreted-text role="func"}
    `phNxpEse_EndOfApdu()`{.interpreted-text role="func"}
    `phNxpEse_close()`{.interpreted-text role="func"}

## Building the Example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).
    1)  select NXMW\_Host to PCLinux64 or Raspbian
    2)  select NXMW\_SMCOM to T1oI2C\_GP1\_0

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

    - Project: `ex_t1oi2c`

Since this is a \"tloi2c\" example, it will work over a plain session
without setting up any authenticated session.

Refer `se-cmake-options`{.interpreted-text role="numref"} \-\--
`se-cmake-options`{.interpreted-text role="ref"}

## Console output

If everything is successful, the output will be similar to:
    `out\_nx\_t1oi2c.rst.txt`

