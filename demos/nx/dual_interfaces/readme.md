# Dual Interfaces Example

This project demonstrates NFC pause feature in a dual interfaces (NFC and I2C interfaces) case.

Refer [**Dual Interface Example**](./ex_dual_interfaces.c)

## Prerequisites

- Hardware: NX SA should be connected to a supported MCU
  or Raspberry Pi.
- Nx middleware stack.
- NTAG configuration tool (e.g. RFIDDiscover) is available on NFC
  host.

## About the Example

The NFC Pause feature allows to transfer control from an NFC Host to an
MCU controlling NTAGECC as a master via the I2C interface. There are 2
ways to activate NFC pause:

- Cmd.ManageGPIO
- Cmd.ISOReadBinary/Cmd.ReadData

When NFC Pause is triggered, NTAGECC shall halt processing on the NFC
interface until the Cmd.ManageGPIO is received on the I2C interface to
release the NFC Pause.

NTAG configuration tool (e.g. RFIDDiscover) on NFC host is used to
trigger NFC pause and this example will release NFC pause.

1. Initialize MCU GPIO as input pin. On FRDM-MCXN947, it is PTB3.
2. Read current GPIO status as initial GPIO status.
3. Read GPIO status at 1s interval and wait until status changes.
4. NFC host(RFIDDiscover) selects NTAGECC application from NFC interface.
5. NFC host(RFIDDiscover) setups symmetric authentication with Secure Authenticator.
6. NFC host(RFIDDiscover) configures GPIO2 for output or output with NFCPause file. If it is latter then NFC Pause file should also be configured. NFC pause file is supposed to be file 2 (can be changed by modifying EX_DUAL_INTERFACE_NFC_PAUSE_FILE_NO in ex_dual_interfaces.c.
7. NFC host(RFIDDiscover) calls Cmd.ManageGPIO with NFC Pause or Cmd.ReadData.
8. ex_dual_interfaces will detect GPIO status change.
9. ex_dual_interfaces will write to NFCPause file.
10. ex_dual_interfaces will call Cmd.ManageGPIO with NFC Pause Release.
11. NFC host(RFIDDiscover) gets response for Cmd.ManageGPIO or Cmd.ReadData.
12. NFC host(RFIDDiscover) calls Cmd.ManageGPIO with NFC Pause or Cmd.ReadData.
13. ex_dual_interfaces will close session.

It uses the following APIs and data types:

- `nx_WriteData()`
- `nx_ManageGPIO_Output()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

    - Project: `ex_dual_interfaces`
    - Select NXMW_Auth to None
    - NXMW_Secure_Tunneling to None

## How to use

Run the tool as: ex_dual_interfaces.exe on windows or ./ex_dual_interfaces on Raspberry Pi.

## Console output

If everything is successful, the output will be similar to:
```
nx_mw :WARN :Communication channel is Plain.
nx_mw :WARN :!!!Security and privacy must be assessed.!!!
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :HOST GPIO (PTB3) Init Status: Low
nx_mw :INFO :HOST GPIO (PTB3) Status Changed: High
nx_mw :INFO :Write NDEF File Data (Offset 0x0, Length 0x8).
nx_mw :INFO :Read External I2C Sensor Could Be Called Here!
nx_mw :INFO :Toggle GPIO2 And Release NFC Pause.
nx_mw :INFO :Read HOST GPIO (PTB3): Low
nx_mw :INFO :Wait session close until NFC pause
nx_mw :INFO :HOST GPIO (PTB3) Status Changed: High
nx_mw :INFO :ex_dual_interfaces Example Success !!!...
nx_mw :INFO :ex_sss Finished
```
