# Certificate Access Right Demo

NTAGECC supports a private extension (ARExtension) for access right
encoding within X.509 certificates. This project and another 2 demos
nx_Personalization and ex_cert_ar_provision together show how the
access right extension takes effect.

ex_cert_ar_provision will create a file (with file number 4) with
FileAR.ReadWrite set to 1.

nx_Personalization will initialize CA Root Key with AC bitmap 0x0FFF
which means access conditions 0x0 - 0xB are granted.

ex_cert_ar_file_op will setup Sigma-I authentication and read this
file. It will fail when using certificate defined
`demos/nx/cert_access_right/cert` because
the certificate access right only grants access condition 0.

If using the certificates in
`binaries/configuration/cert_depth3_PKCS7_rev1`, ex_cert_ar_file_op will pass because those
certificates don\'t include access right extension. So access right is
inherited from CA Root Key.

## Pre-requisites

-   `nx_Personalization` should run first with AC bitmap0 and bitmap1 set.
Also certificates used are defined in `demos/nx/cert_access_right/cert`.

-   `nx_Personalization` will initialize the certificates and keypairs for Sigma-I authentication.

-   `ex_cert_ar_file_op` should run with certificates defined in `demos/nx/cert_access_right/cert`.

For Windows or Linux Like platform, it means set environment variable `NX_AUTH_CERT_DIR` to the certificate path.

For MCU like K64F, it means changing the certificates defined in `sss/ex/inc/ex_sss_nx_auth.h`


## Building the Example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

	-   Project: `ex_cert_ar_file_op`
	-   Select NXMW_Auth to `NXMW_Auth=SIGMA_I_Verifier` or `NXMW_Auth=SIGMA_I_Prover`


## Running the Example

If you have built a binary, flash the binary on to the board and reset the board.

```
If you have built an *exe* to be run from Windows, run as:

ex_cert_ar_file_op.exe <PORT NAME>
```

```
On Linux, run as:

./ex_cert_ar_file_op
```

## Console output
If everything is successful, the output will be similar to:
```
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Running File Management Example ex_cert_ar_file_op.c
nx_mw :WARN :nxEnsure:'(ret == SM_OK) || (ret == SM_OK_ALT)' failed. At Line:3735 Function:sss_nx_TXn_AES_EV2
nx_mw :INFO :File read failed. Expected result if uses certificates of this demo !!!
nx_mw :INFO :ex_cert_ar_file_op Example Success !!!...
nx_mw :INFO :ex_sss Finishe
```
