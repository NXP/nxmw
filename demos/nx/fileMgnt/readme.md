# File Management Example

This project demonstrates basic File Management operations using Nx APIs.

Refer [**File Management Example**](./ex_sss_file_mgnt.c)

## About the Example

This example creates a file, writes and reads data from it.

**Note** - The fileNo 1, 2 and 3 cannot be used, as there are some pre-provisioned static files present at these IDs.

It uses the following APIs and data types:
    `nx_GetFileIDs()`
    `nx_CreateStdDataFile()`
    `nx_WriteData()`
    `nx_ReadData()`

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
	- Project - `ex_file_mgnt`
	- Select NXMW_Auth to SIGMA_I_Verifier, SIGMA_I_Prover or Symm_Auth.-
	- NXMW_Secure_Tunneling to NTAG_AES128_EV2, NTAG_AES256_EV2 or NTAG_AES128_AES256_EV2.

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Running File Management Example ex_sss_file_mgnt.c
App   :INFO :Standard Data File creation successful !!!
App   :INFO :File write successful !!!
App   :INFO :File read successful !!!
App   :INFO :ex_sss_file_mgnt Example Success !!!...
App   :INFO :ex_sss Finished
```
