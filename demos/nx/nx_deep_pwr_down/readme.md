# NX Deep Power down example

This project is used to demonstrate the deep power down on NX SA using
T=1oI2C command.

The example will send a proprietary deep power down command (as
described in the Datasheet) via I2C link to bring the device into the
deep power down mode. The example will wait for 10 seconds before
reopening the session which will also make the secure element wakeup
from deep power down mode.

## Building the Demo

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

	- Project - `nx_deep_pwr_down`

## Running the Example

If you have built a binary, flash the binary on to the board and reset the board.

If you have built an *exe* to be run from Windows using VCOM, run as:

```
nx_deep_pwr_down.exe <PORT NAME>
```

Where **\<PORT NAME\>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run as:

```
./nx_deep_pwr_down
```

## Console Output

If everything is successful, the output will be similar to:

```
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :session_ctx->authType 0
nx_mw :INFO :Available free memory: 17632 bytes
nx_mw :INFO :Send deep power down command to the IC

nx_mw :INFO :Sleep for 10 seconds

nx_mw :INFO :cip (Len=22)
      01 04 63 07    00 93 02 08    00 02 03 E8    00 01 00 64
      04 03 E8 00    FE 00
nx_mw :WARN :Communication channel is Plain.
nx_mw :WARN :!!!Security and privacy must be assessed.!!!
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :session_ctx->authType 0
nx_mw :INFO :Available free memory: 17632 bytes
nx_mw :INFO :nx_deep_pwr_down Example Success !!!...
nx_mw :INFO :ex_sss Finished
```
