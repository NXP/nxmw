# Provision For Certificate Access Right Demo

NTAGECC supports a private extension (ARExtension) for access right
encoding within X.509 certificates. This project and another 2 demos
nx_Personalization and ex_cert_ar_file_op togther show how the
access right extension takes effect.

ex_cert_ar_provision will create a file (with file number 4) with
FileAR.ReadWrite set to 1. ex_cert_ar_file_op will then read this
file.

## Pre-requisites

-   If compiled with `NXMW_Auth=SIGMA_I_Verifier` or
    `NXMW_Auth=SIGMA_I_Prover` then `nx_Personalization` should run
    first with AC bitmap0 set at least. Also certificates used are
    defined in `demos/nx/cert_access_right/cert`{.interpreted-text
    role="file"}. `nx_Personalization` will initialize the certificates
    and keypairs for Sigma-I authentication.

-   If compiled with `NXMW_Auth=SIGMA_I_Verifier` or
    `NXMW_Auth=SIGMA_I_Prover`, `ex_cert_ar_provision` should run with
    certificates defined in
    `demos/nx/cert_access_right/cert`.
    For Windows or Linux Like platform, it means set environment
    variable `NX_AUTH_CERT_DIR` to the certificate path. For MCU like
    K64F, it means changing the certificates defined in
    `sss/ex/inc/ex_sss_nx_auth.h`


## Building the Example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

    - Project: `ex_cert_ar_provision`

    - Select NXMW_Auth to `NXMW_Auth=SIGMA_I_Verifier` or `NXMW_Auth=SIGMA_I_Prover` or `NXMW_Auth=SYMM_Auth`

    - If `NXMW_Auth=SYMM_Auth` then `NXMW_Auth_Symm_App_Key_Id=0` should be selected.


## Running the Example

If you have built a binary, flash the binary on to the board and reset the board.

```
If you have built an *exe* to be run from Windows, run as:

ex_cert_ar_provision.exe <PORT NAME>
```

```
On Linux, run as:

./ex_cert_ar_provision
```

## Console output
If everything is successful, the output will be similar to:
```
App   :INFO :NX_PKG_v01.01.01_20230804
App   :INFO :Running ex_cert_ar_provision.exe
App   :INFO :Using PortName='COM10' (ENV: EX_SSS_BOOT_SSS_PORT=COM10)
App   :INFO :Using default PCDCap2. You can use PCDCap2 from file using ENV=EX_SSS_BOOT_PCDCAP2_PATH
App   :INFO :Using default appkey. You can use appkeys from file using ENV=EX_SSS_BOOT_APPKEY_PATH
Opening COM Port '\\.\COM10'
sss   :INFO :atr (Len=22)
      01 04 63 07    00 93 02 08    00 02 03 E8    00 01 00 64
      04 03 E8 00    FE 00
sss   :INFO :Session Open Succeed
App   :INFO :Running Provision For Certificate Access Right Example ex_cert_ar_provision.c
App   :INFO :Create Standard Data File With ReadWriteAccess 0x1 !!!
App   :INFO :ex_cert_ar_provision Example Success !!!...
App   :INFO :ex_sss Finished
```
