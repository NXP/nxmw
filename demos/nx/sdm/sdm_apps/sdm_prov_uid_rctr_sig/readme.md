# SDM Provision to enable plain VCUID, Readcounter mirroring and Sign operation

This project is used to enable and configure SDM. After running this
demo, ex_sdm_prov_uid_rctr_sig/ex_sdm_prov_uid_rctr_sig can be used to read out data from
file, piccdata and verify the signature.

In detail, this demo will do following:

- Read application leaf certificate
- Update Meta Data for existing application ECC key, KeyID 0 with policy, enable sdm application
- Change Read-Only access rights in CC file, using cmd.nx_writeData on fileNo1 at offset 0xE  
- Change file 2 setting
    1. Enable Secure Dynamic Messaging and Mirroring
    2. Disable Deferred Configuration
    3. Enable VCUID mirroring 
    4. Enable SDMReadCtr mirroring
    5. Disable SDMReadCtrLimit
    6. Encrypt PICCData mirroring with Plain PICCData mirroring
    7. Enable SDM File Data Sign with ECC Key 0 (`EX_SSS_SDM_ECC_KEY_ID`) or
    8. Enable SDM File Data with MAC (`Nx_SDMFileRead_AccessCondition_No_SDM`)
    9. Access condition for Cmd.GetFileCounters is 0.
    10. SDM input data for signature start at offset 0x10 (`EX_SSS_SDM_SDMMACInputOffset`)
    11. PICCData is mapped to offset 0x20 (`EX_SSS_SDM_PICCDATA_OFFSET`)
    12. SDM signature start at offset 0x43 (`EX_SSS_SDM_SDMMACOffset`)
- Write url data on NDEF file, using cmd.nx_writeData

## Building the Demo

- Build NX middleware stack. Refer [**Linux build**](../../../../doc/linux/readme.md).

  - Select CMake options:
    - `NXMW_All_Auth_Code=Enabled`
    - `NXMW_Auth=SYMM_Auth`
    - `NXMW_Auth_Symm_App_Key_Id=0`
    - `NXMW_SA_Type=NTAG_X_DNA`
    
  - project - `ex_sdm_prov_uid_rctr_sig`

## Running the Example

```
./ex_sdm_prov_uid_rctr_sig
```

## Console output

If everything is successful, the output will be similar to:
```
nx_mw :INFO :NX_PKG_v02.05.01_20250515
nx_mw :WARN :mbedtls_entropy_func_3_X is a dummy implementation with hardcoded entropy. Mandatory to port it to the Micro Controller being used.
nx_mw :INFO :cip (Len=22)
                01 04 63 07     00 93 02 08     00 02 03 E8     00 01 00 64
                04 03 E8 00     FE 00
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Change File 2 Setting.
nx_mw :INFO :SDM Enable: 1
nx_mw :INFO :VCUID Enable: 1
nx_mw :INFO :SDMReadCtr Enable: 1
nx_mw :INFO :SDMMetaRead: 0xe
nx_mw :INFO :SDMFileRead: 0x1
nx_mw :INFO :SDMFileRead2: 0x0
nx_mw :INFO :VCUIDOffset: 0x1b
nx_mw :INFO :SDMReadCtrOffset: 0x2c
nx_mw :INFO :PICCDataOffset: 0x20
nx_mw :INFO :SDMMACInputOffset: 0x1b
nx_mw :INFO :SDMMACOffset: 0x35
nx_mw :INFO :NDEF URL Untag.nxp.com/xdna?m=01020304050607&c=001122&s=11223344556677881122334455667788112233445566778811223344556677881122334455667788112233445566778811223344556677881122334455667788

nx_mw :INFO :ex_sdm_prov_uid_rctr_sig Example Success !!!...
nx_mw :INFO :ex_sss Finished
```