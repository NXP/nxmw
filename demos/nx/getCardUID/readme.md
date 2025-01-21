# Get Card UID Example

This project demonstrates getting card UID operation using Nx APIs.

Refer [**Get Card UID Example**](./ex_sss_get_uid.c)

## About the Example

This example shows a simple operation to read the card UID.

It uses the following APIs and data types:
	-`nx_GetCardUID()`

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
	- Project : `ex_get_uid`
	- Select NXMW_Auth to SIGMA_I_Verifier, SIGMA_I_Prover or Symm_Auth.-
	- NXMW_Secure_Tunneling to NTAG_AES128_EV2, NTAG_AES256_EV2 or NTAG_AES128_AES256_EV2.

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Running Get Card UID Example ex_sss_get_uid.c
App   :INFO :Get Card UID
App   :INFO :Successful !!!
App   :INFO :Card UID (Len=7)
      00 01 02 03    04 05 06
App   :INFO :ex_sss_get_uid Example Success !!!...
App   :INFO :ex_sss Finished
```

