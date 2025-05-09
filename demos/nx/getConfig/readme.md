# Get Configuration Example

This project demonstrates get configuration operation using SSS APIs. It
will read manufacturing product features and card configuration.

Refer [**Get Configuration Example**](./ex_sss_get_config.c)


## About the Example

This example does a get configuration operation.

It uses the following APIs and data types:

    `nx_GetConfig_ManufactureConfig()`
    `nx_GetConfig_PICCConfig()`
    `nx_GetConfig_ATSUpdate()`
    `nx_GetConfig_SAKUpdate()`
    `nx_GetConfig_SMConfig()`
    `nx_GetConfig_CapData()`
    `nx_GetConfig_ATQAUpdate()`
    `nx_GetConfig_SilentModeConfig()`
    `nx_GetConfig_EnhancedPrivacyConfig()`
    `nx_GetConfig_NFCMgmt()`
    `nx_GetConfig_I2CMgmt()`
    `nx_GetConfig_GPIOMgmt()`
    `nx_GetConfig_EccKeyMgmt()`
    `nx_GetConfig_CertMgmt()`
    `nx_GetConfig_WatchdogTimerMgmt()`
    `nx_GetConfig_CryptoAPIMgmt()`
    `nx_GetConfig_LockConfig()`


## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

    - Project - `ex_get_config`
    - Select NXMW_Auth to SIGMA_I_Verifier, SIGMA_I_Prover or SYMM_Auth.
    - NXMW_Secure_Tunneling to NTAG_AES128_EV2, NTAG_AES256_EV2 or NTAG_AES128_AES256_EV2 (only with SIGMA_I_Verifier or SIGMA_I_Prover).
    - The authentication must be setup with access condition 0. This means App Master key for symmetric authentication. For Sigma-I authentication, this mean AC0 of certificate
        access right. It is defined with CA root key and reader certificate (or certificate chain).

>**Note:** GetConfig Demo on MCXA153 currently supports Sigma Authentication with Mbedtls2. Symmetric Authentication is supported with Mbedtls 2 and Mbedtls 3. 

## Console output

If everything is successful, the output will be similar to:

```
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Running Get Configuration Example ex_sss_set_config.c

APDU  :DEBUG:GetConfiguration [manufacturer configuration]
nx_mw :INFO :=======================================
nx_mw :INFO :Get Manufacture Features successful !!!
nx_mw :INFO : Support ECC-based Unilateral Authentication: Enabled
nx_mw :INFO : Support Import of ECC Private Key: Enabled
... OTHER DETAILS ...
nx_mw :INFO :ex_sss_get_config Example Success !!!...
nx_mw :INFO :ex_sss Finished
```

