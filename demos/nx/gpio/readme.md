# GPIO Example

This project demonstrates a GPIO output / input operation using Nx APIs.

Refer [**GPIO Example**](./ex_sss_gpio.c)

## Prerequisites

-   Hardware: NX SA should be connected to FRDM-K64F board or Raspberry Pi.
-   GPIO1 should be already been configured to output and GPIO2 should
    be configured to input. [**nx_tool_setconfig**](../nx_tool_setconfig/readme.md) or
    [**ex_set_config**](../setConfig/readme.md) can be used for configuration.

## About the Example

This example does a GPIO output / input operation.

It uses the following APIs and data types: (including the ones used to control host board GPIOs)

    `nx_ManageGPIO_Output()`
    `nx_ReadGPIO()`
    `nx_host_GPIOInit()`
    `nx_host_GPIORead()`
    `nx_host_GPIOClear()`
    `nx_host_GPIOSet()`
    `nx_host_GPIOClose()`
    `nx_host_GPIOClose()`
    `GPIO_PinInit()`
    `GPIO_PinRead()`
    `GPIO_PortClear()`
    `GPIO_PortSet()`

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
    - Project - `ex_gpio`
    - NXMW_Auth and NXMW_Secure_Tunneling should be selected according to simulator/IC configuration.

## How to Run example

    ./nx_tool_setconfig -gpio1mode output -gpio2mode input -gpioMgmtCM full -gpioReadCM full -gpioMgmtAC 0x0 -gpioReadAC 0x0

## Console output

If everything is successful, the output will be similar to:

```
sss   :INFO :Session Open Succeed
App   :INFO :Clear GPIO1.
App   :INFO :Read HOST GPIO (PTB2): Low
App   :INFO :Set GPIO1.
App   :INFO :Read HOST GPIO (PTB2): High
App   :INFO :Toggle GPIO1.
App   :INFO :Read HOST GPIO (PTB2): Low
App   :INFO :Set HOST GPIO (PTB3): Low
App   :INFO :Read GPIO2 is low.
App   :INFO :Set HOST GPIO (PTB3): High
App   :INFO :Read GPIO2 is low.
App   :INFO :ex_sss_gpio Example Success !!!...
App   :INFO :ex_sss Finished
```
