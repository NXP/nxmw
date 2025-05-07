# Get Version Example

This project demonstrates a get HW/SW version using Nx APIs.

Refer [**Get version Example**](./ex_sss_get_version.c)

## About the Example

This example does a getting HW/SW version operation along with the manufacturing info.

It uses the following APIs and data types: `nx_GetVersion()`

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

	- Project - `ex_get_version`
	- Select NXMW_Auth to None, SIGMA_I_Verifier, SIGMA_I_Prover or SYMM_Auth.
	- NXMW_Secure_Tunneling to None (only with NXMW_Auth None), NTAG_AES128_EV2,
	  NTAG_AES256_EV2 or NTAG_AES128_AES256_EV2 (only with NXMW_Auth SIGMA_I_Verifier or SIGMA_I_Prover).

## Console output

If everything is successful, the output will be similar to:

```
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Running Get Card Version Example ex_sss_get_version.c
nx_mw :INFO :Get Card Version
nx_mw :INFO :Successful !!!
nx_mw :INFO :HW Vendor ID: NXP Semiconductors
nx_mw :INFO :HW type: IoT
nx_mw :INFO :HW subtype: 17 pF, Tag Tamper
nx_mw :INFO :HW major version: NX (Zen-V)
nx_mw :INFO :HW minor version 0x0
nx_mw :INFO :HW storage size: 16 kB
nx_mw :INFO :HW protocol type: I2C and ISO/IEC 14443-4 support with Silent Mode support
nx_mw :INFO :SW Vendor ID: NXP Semiconductors
nx_mw :INFO :SW type: IoT
nx_mw :INFO :SW subtype: Standalone
nx_mw :INFO :SW major version: EV0
nx_mw :INFO :SW minor version 0xec
nx_mw :INFO :SW storage size: 16 kB
nx_mw :INFO :SW protocol type: I2C and ISO/IEC 14443-4 support with Silent Mode support
nx_mw :INFO :UIDFormat: 0x0
nx_mw :INFO :UIDLength: 0xa
nx_mw :INFO :Card UID (Len=10)
      00 01 02 2C    41 01 01 07    08 09
nx_mw :INFO :BatchNo: 0x0
nx_mw :INFO :FabKey identifier: 0x0
nx_mw :INFO :Calendar week of card production in BCD coding: 0x31
nx_mw :INFO :The year of production in BCD coding: 0x22
nx_mw :INFO :Fab Identifier: 0x32
nx_mw :INFO :ex_sss_get_version Example Success !!!...
nx_mw :INFO :ex_sss Finished
```

