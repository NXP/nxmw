# NX Release Request Command example

This project is used to demonstrate the release request command on NX
using T=1oI2C API.

## Build

Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).

- Project - ``nx_release_req_cmd``

- Set NXMW_Host as the appropriate platform

## Running the Example

For board, flash the built binary on the board and reset.

On Windows (to run using VCOM), run the generated executable as:

```
nx_release_req_cmd.exe <PORT NAME>
```

Where **\<PORT NAME\>** is the VCOM COM port.

On Raspberry-Pi or iMX board, run the generated binary as:

```
./nx_release_req_cmd
```

## Console Output

If everything is successful, the output will be similar to:

```
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Send release req command the IC

nx_mw :INFO :Sleep for 10 seconds

nx_mw :INFO :session_ctx->authType 5
nx_mw :INFO :Available free memory: 8672 bytes
nx_mw :INFO :nx_release_req_cmd Example Success !!!...
nx_mw :INFO :ex_sss Finished
```