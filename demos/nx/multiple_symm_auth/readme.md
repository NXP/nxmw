# Multiple Symmetric Authentication Example

This project demonstrates Multiple Symmetric Authentication using SSS APIs

Refer [**Multiple symmetric authentication**](./ex_multiple_symm_auth.c)

## About the Example

AES-based symmetric authentication is managed by
Cmd.AuthenticateEV2First and Cmd.AuthenticateEV2-NonFirst. A First
Authentication is done in state VCState.NotAuthenticated or in one of
the authenticated states. The Non-First Authentication can only be
applied after a First Authentication, i.e. in an authenticated state.

This example demonstrate how to setup 2 symmetric authentications with
Cmd.AuthenticateEV2First and Cmd.AuthenticateEV2-NonFirst.

- Open session 1 with symmetric authentication i.e.
  cmd.authenticateEV2First. AES128 or AES256 session keys are
  generated which are used for EV2 secure messaging.
- Create and write file with session 1 EV2 secure tunneling.
- Bind session 2 to session 1. This allows cryptographically binding
  all messages within a transaction by using a transaction identifier
  TI and command counter CmdCtr.
- Open session 2 with symmetric authentication i.e.
  cmd.authenticateNonFirst. Session keys are re-generated.
- Read file with session 2 EV2 secure tunneling.

It uses the following APIs and data types:
    `sss_session_open()`
    `ex_sss_session_close()`
    `nx_CreateStdDataFile()`
    `nx_WriteData()`
    `nx_ReadData()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

  - Project - `ex_multiple_symm_auth`
  - `NXMW_Auth=SYMM_Auth`
  - `NXMW_Auth_Symm_App_Key_Id=0`

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Standard Data File creation successful !!!
App   :INFO :File write successful !!!
App   :INFO :Bind session 1 to session 2
App   :INFO :Using default appkey. You can use appkeys from file by setting ENV=EX_SSS_BOOT_APPKEY_PATH to its path
App   :INFO :Trying to open session 2
sss   :INFO :Session Open Succeed
App   :INFO :File read successful !!!
App   :INFO :Unbind session 2
App   :INFO :Session 2 close
App   :INFO :ex_multiple_symm_auth Example Success !!!...
App   :INFO :ex_sss Finished
```

