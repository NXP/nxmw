# Multiple sessions (Plain and Sigma-I) Example

This project demonstrates opening and closing a plain session followed
by a Sigma-I session out of the box.

**Refer** [**multiple_sessions**](./ex_sss_multiple_sessions.c)

## Prerequisites

- Nx middleware stack. **Refer** [**MW stack**](../../../doc/stack/readme.md)
- nx_Personalization example is built and run using the same curve type
  (NXMW_Auth_Asymm_Host_Curve) as is used in the example
  (cert_curve_type, ephem_curve_type).

## About the Example

In this example, it is shown how can one open a plain session, perform
an API call, close it and follow it the same for a Sigma-I session,
**without** using the common header ex_sss_main_inc.h generally used in
other examples.

It uses the following APIs and data types: -

  - `sss_session_open` -
  - `kSSS_ConnectionType_Plain`
  - `sss_connection_type_t`
  - `kSSS_ConnectionType_Encrypted`
  - `sss_connection_type_t` 
  - `sss_session_close`
  - `sss_host_session_close`

## Building the example 

- Build NX middleware stack. **Refer** [**Cmake_build**](../../../doc/mcu_cmake/readme.md).

  - Project -  `ex_sss_multiple_sessions`

## Console output

If everything is successful, the output will be similar to:

```
nx_mw :INFO :Open plain session

nx_mw :INFO :cip (Len=22)
                01 04 63 07     00 93 02 08     00 02 03 E8     00 01 00 64
                04 03 E8 00     FE 00
nx_mw :WARN :Communication channel is Plain.
nx_mw :WARN :!!!Security and privacy must be assessed.!!!
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :session_ctx->authType 0
nx_mw :INFO :Available free memory = 8352
nx_mw :INFO :Close plain session

nx_mw :INFO :Init Host for Sigma-I session (AES128_NTAG)

nx_mw :WARN :mbedtls_entropy_func_3_X is a dummy implementation with hardcoded entropy. Mandatory to port it to the Micro Controller being used.
nx_mw :INFO :Using certificate/key from lib/sss/inc/fsl_sss_nx_auth_keys.h (cert_depth3_x509_rev1)
nx_mw :INFO :cip (Len=22)
                01 04 63 07     00 93 02 08     00 02 03 E8     00 01 00 64
                04 03 E8 00     FE 00
nx_mw :INFO :Using root certificate from lib/sss/inc/fsl_sss_nx_auth_keys.h
nx_mw :INFO :Verify X.509 certificate with root/cached CA certificate failed
nx_mw :INFO :Verify X.509 certificate with root/cached CA certificate failed
nx_mw :INFO :Verify X.509 certificate with certificate(C=NL, ST=Eindhoven, L=Eindhoven, O=NXP, CN=NXP Auth RootCAvE201) Passed
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Random bytes generated (Len=32)
                A8 46 04 39     12 03 0C A9     CB BB D1 BB     13 E1 CE CC
                B5 41 68 7B     22 2D 46 4B     36 18 90 CD     64 BD DA 65
nx_mw :INFO :Close sigma-i session

nx_mw :INFO :gex_sss_multiple_sessions Example Success !!!...
```