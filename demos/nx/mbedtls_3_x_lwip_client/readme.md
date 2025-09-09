# Mbedtls lwip client Example

Mbed TLS client and server example can be used to test the Mbed TLS ALT with MCUs.

- Project: `mbedtls_3_x_lwip_client`

This project demonstrates a mbedtls lwip client operation using Nx APIs.

Refer [**lwip client Example**](./ex_sss_ssl2.c)

## Prerequisites

- generate certificates and provision the keys in SA Refer [**Create and Provision Script**](../../../plugin/mbedtls3x/scripts/create_and_provision_ecc_keys.py)   

- copy the generated keys tls_root_ca certificate, tls_client certificate and tls_client_key_ref in Refer [**header file**](./ecc_keys.h)

- keep server open by running the mbedtls_3x_server

**IMPORTANT**
This is a demo example. Before actual deployment check for CVEs and MBEDTLS security vulnerabilites for your MBEDTLS version.

>**Note:** 
    To run mbedtls_3_x_lwip_client example on plain commMode or none authentication.
    set access condition plain mode for Cmd.CryptoRequest, which can be configured
    through Cmd.SetConfiguration Option 0x15 and 0x12 (Refer [**nx_tool_setconfig**](../nx_tool_setconfig/readme.md)).
    Example:

          nx_tool_setconfig.exe -cryptoCM plain -cryptoAC 0xE COM10

## About the Example

Mbed TLS ALT implementation allows Mbed TLS stack use the secure
authenticator access using SSS layer. Crypto operations performed using
the secure authenticator during tls hand-shake.

## Building the Example

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

- Build client example with ALT option enabled. Refer [**Introduction on Mbed TLS (3.x) ALT Implementation**](../../../plugin/mbedtls3x/readme.md).

    - `-DPTMW_mbedTLS_ALT:STRING=SSS`
    - `-DNXMW_RTOS=FreeRTOS`
    - `-DNXMW_Host=frdmmcxn947`
    - `-DNXMW_MBedTLS=3_X`
    - `-DNXMW_HostCrypto=MBEDTLS`

## How to Run Example

```
./mbedtls_3_x_lwip_client
```