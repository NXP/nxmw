# NX Minimal example

This project gets available memory from Secure Authenticator.

## About the Example

This project gets available memory from Secure Authenticator.

It uses the following API:
	`nx_FreeMem()`

## Building the Example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).
-
	- Project - `nx_Minimal`

Since this is a "minimal" example, it is expected to work over a plain session without setting up any authentication.

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :memSize=17728
App   :INFO :nx_Minimal Example Success !!!...
App   :INFO :ex_sss Finished
```

