# Set Configuration Example

This project demonstrates a set configuration operation using NX APIs.
It will set GPIO1 to output mode and GPIO2 to input mode. The
communication mode for managing and reading gpio is set to full protect.
The access condition for managing and reading gpio is set to 1.

Refer [**Set Configuration Example**](./ex_sss_set_config.c)

## About the Example

This example does a set configuration operation.

It uses the following APIs and data types:

    `nx_SetConfig_GPIOMgmt()`
    `nx_SetConfig_WatchdogTimerMgmt()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

    - Project - `ex_set_config`

    - Select NXMW_Auth to SIGMA_I_Verifier, SIGMA_I_Prover or SYMM_Auth

    - NXMW_Secure_Tunneling to NTAG_AES128_EV2, NTAG_AES256_EV2 or NTAG_AES128_AES256_EV2 (only with SIGMA_I_Verifier or SIGMA_I_Prover)

    - The authentication must be setup with access condition 0. This means App Master key for symmetric authentication. For Sigma-I authentication, this mean AC0 of certificate access right. It\'s defined with CA root key and reader certificate (or certificate chain).

    - Set watch dog timer by enabling macro SET_CONFIG_WATCHDOG_TIMER_ENABLE 1.
        Adjust timer value 0-60sec using macro
        SET_CONFIG_WATCHDOG_TIMER_HWDTVALUE
        SET_CONFIG_WATCHDOG_TIMER_AWDT1VALUE
        SET_CONFIG_WATCHDOG_TIMER_AWDT2VALUE

Refer - [**ex_sss_set_config.h**](./ex_sss_set_config.h)

## How to use

Run the tool as:

```
./ex_set_config
```

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Running Set Configuration Example ex_sss_set_config.c
App   :INFO :Set GPIO1 to output and GPIO2 to input.
App   :INFO :Set ManageGPIO access condition to full protection and access condition 1.
App   :INFO :Set Configuration successful !!!
App   :INFO :ex_sss_set_config Example Success !!!...
App   :INFO :ex_sss Finished
```

