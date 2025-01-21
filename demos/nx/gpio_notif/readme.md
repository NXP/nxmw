# GPIO Notification Example

This project demonstrates a GPIO Notification operation using Nx APIs.

Refer [**Get GPIO Notification Example**](./ex_sss_gpio_notif.c)

## Prerequisites

-   Hardware: NX SA should be connected to FRDM-K64F board or Raspberry Pi.
-   GPIO1 should be already configured to output and also enable GPIO1
    has GPIONotif. "nx_tool_setconfig"(Refer `nx_tool_setconfig`) or
    "ex_set_config" (GPIO1 notification should be enabled by setting
    macro SET_CONFIG_GPIO_NOTIFY_ENABLE=1. Refer `ex-sss-set-config`)
    can be used for configuration.

## About the Example

This example does a GPIO Notif operation on authentication and read the status of GPIO.

The targeted GPIO will be HIGH, after successful execution of SIGMA-I
mutual authentication, i.e. when a session is opened with SIGMA_I The
targeted GPIO will be LOW, when losing authentication state, e.g. when a
session is opened with none authentication.

It uses the following APIs and data types:

    `sss_session_open()`
    `nx_host_GPIOInit()`
    `nx_host_GPIORead()`
    `sss_session_close()`

## Building the Example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
  - Project - `ex_gpio_notif`
  - `NXMW_Auth=SIGMA_I_Verifier` `NXMW_Secure_Tunneling=NTAG_AES128_EV2`
    and `NXMW_All_Auth_Code=Enabled` should be selected according to IC configuration.


## How to Run Example

```
./nx_tool_setconfig -gpio1mode output -gpio1Notif auth -gpioMgmtCM full -gpioReadCM full -gpioMgmtAC 0x0 -gpioReadAC 0x0
```

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Successfully opened SIGMA-session
App   :INFO :Read GPIONotif: High
Opening COM Port '\\.\COM10'

 Already  COM Port Open
 sss   :INFO :atr (Len=22)
      01 04 63 07    00 93 02 08    00 02 03 E8    00 01 00 64
      04 03 E8 00    FE 00
sss   :WARN :Communication channel is Plain.
sss   :WARN :!!!Not recommended for production use.!!!
sss   :INFO :Session Open Succeed
App   :INFO :Successfully opened Plain-session
App   :INFO :Read GPIONotif: Low
App   :INFO :ex_sss Finished
```
