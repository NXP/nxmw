# Dual Interfaces Example

This project demonstrates NFC pause feature in a dual interfaces (NFC and I2C interfaces) case.

Refer [**Dual Interface Example**](./ex_dual_interfaces.c)

## Prerequisites

- Hardware: NX SA should be connected to a supported MCU
  or Raspberry Pi.
- Nx middleware stack.
- NTAG configuration tool (e.g. RFIDDiscover) is available on NFC
  host **Refer application note** AN14513 NTAG X DNA - Dual Interface.
- The NFC Pause feature with Cmd.ManageGPIO Using nx_tool_setconfig configures GPIO2 for output and GPIO High speed mode and Initial state low.
- nx_tool_setconfig (built for VCOM)
  ```
  ./nx_tool_setconfig -gpio2mode output -gpio2config 0x00 -gpio2padctrlD gpio_high_speed_2 -gpioMgmtCM plain -gpioReadCM plain -gpioMgmtAC 0xE -gpioReadAC 0xE COM6
  ```
- The NFC Pause feature with Cmd.ISOReadBinary/Cmd.ReadData Using nx_tool_setconfig configures GPIO2 for output with nfc pause file and GPIO High speed mode, Initial state low, NFCPause fileNumber, NFCPauseOffset and NFCPauseLength.
- nx_tool_setconfig (built for VCOM)
  ```
  ./nx_tool_setconfig -gpio2mode out_nfcpausefile -gpio2config 0x00 -gpio2padctrlD gpio_high_speed_2 -gpioMgmtCM plain -gpioReadCM plain -gpioMgmtAC 0xE -gpioReadAC 0xE -nfcpausefileno 0x02 -nfcpauseoffset 0x020000 -nfcpauselength 0x0F0000 COM6
  ```
## About the Example

The NFC Pause feature allows to transfer control from an NFC Host to an
MCU controlling NTAGECC as a master via the I2C interface. There are 2
ways to activate NFC pause:

- Cmd.ManageGPIO
- Cmd.ISOReadBinary/Cmd.ReadData

When NFC Pause is triggered, NTAGECC shall halt processing on the NFC
interface until the Cmd.ManageGPIO is received on the I2C interface to
release the NFC Pause.

Steps for NFC Operation using Cmd.ManageGPIO

  - ex_dual_interfaces will initialize MCU GPIO as input pin. On FRDM-MCXN947, it is PTB3.
  - ex_dual_interfaces will read current GPIO status as initial GPIO status.
  - ex_dual_interfaces will read GPIO status at 1s interval and wait until status changes.
  - NFC host(RFIDDiscover) selects NTAGECC application from NFC interface.
      1. Press "RF Reset", to turn RF field OFF and ON again
      2. Press "Activate Idle" to perform ISO1444-3 activation
      3. Press "RATS + PPS" to perform ISO1444-4 activation
      4. Choose "Select" sub-menu under NTAG → NTAG X DNA → ISO 7816-4 Support
      5. Choose "Select by DF name" (enter NDEF Application's DF name, if not predefined yet)
      6. Press "Select". At this point, NDEF Application is selected.
  - NFC host(RFIDDiscover) calls Cmd.ManageGPIO with NFC Pause.
      1. Choose "Manage GPIO" sub-menu under NTAG → NTAG X DNA → ISO 7816-4 Support
      2. Select "GPIO2" radio button
      3. Select "NFC Action"
      4. Choose "Toggle"
      5. Press "Manage GPIO"
  - ex_dual_interfaces will detect GPIO status change.
  - ex_dual_interfaces will write to NFCPause file.
  - ex_dual_interfaces will call Cmd.ManageGPIO with NFC Pause Release.
  - NFC host(RFIDDiscover) gets response for Cmd.ManageGPIO.
  - NFC host(RFIDDiscover) calls Cmd.ManageGPIO with NFC Pause.
      1. Choose "Manage GPIO" sub-menu under NTAG → NTAG X DNA → ISO 7816-4 Support
      2. Select "GPIO2" radio button
      3. UnSelect "No NFC Action"
      4. Choose "Toggle"
      5. Press "Manage GPIO"
  - ex_dual_interfaces will close session.


Steps for NFC Operation using Cmd.ISOReadBinary/Cmd.ReadData

  - ex_dual_interfaces will initialize MCU GPIO as input pin. On FRDM-MCXN947, it is PTB3.
  - ex_dual_interfaces will read current GPIO status as initial GPIO status.
  - ex_dual_interfaces will read GPIO status at 1s interval and wait until status changes.
  - NFC host(RFIDDiscover) selects NTAGECC application from NFC interface.
      1. Press "RF Reset", to turn RF field OFF and ON again
      2. Press "Activate Idle" to perform ISO1444-3 activation
      3. Press "RATS + PPS" to perform ISO1444-4 activation
      4. Choose "Select" sub-menu under NTAG → NTAG X DNA → ISO 7816-4 Support
      5. Choose "Select by DF name" (enter NDEF Application's DF name, if not predefined yet)
      6. Press "Select". At this point, NDEF Application is selected.
  - These steps are not needed if NDEF file will be read by Cmd.ReadData
      1. Choose "Select" sub-menu under NTAG → NTAG X DNA → ISO 7816-4 Support
      2. Choose "Select EF under Current DF"
      3. Press "Select". At this point, NDEF File (0xE104) is selected.
  - NFC host(RFIDDiscover) calls Cmd.ISOReadBinary with NFC Pause.
      1. Choose "Read Update Binary" sub-menu under NTAG → NTAG X DNA → ISO 7816-4 Support
      2. Enter desired length to be read
      3. Press "Read Binary".
  - ex_dual_interfaces will detect GPIO status change.
  - ex_dual_interfaces will write to NFCPause file.
  - ex_dual_interfaces will call Cmd.ManageGPIO with NFC Pause Release.
  - NFC host(RFIDDiscover) gets response for Cmd.ManageGPIO.
  - NFC host(RFIDDiscover) calls Cmd.ManageGPIO with NFC Pause.
      1. Choose "Manage GPIO" sub-menu under NTAG → NTAG X DNA → ISO 7816-4 Support
      2. Select "GPIO2" radio button
      3. UnSelect "No NFC Action"
      4. Choose "Toggle"
      5. Press "Manage GPIO"
  - ex_dual_interfaces will close session.

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
