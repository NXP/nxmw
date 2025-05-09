# Secure Dynamic Messaging (SDM) Provisioning Demo

The Secure Dynamic Messaging (SDM) allows for confidential and integrity
protected data exchange, without requiring a preceding authentication.

NTAGECC supports two modes for integrity protection and authentication of the data:

- symmetric SDMMAC
- asymmetric SDMSIG

NTAGECC also support encryption based on symmetric cryptography for
PICCData and generic file data.

This project is used to enable and configure SDM. After running this
demo, ex_sdm_mac/ex_sdm_file_read can be used to read out data from
file and decrypt the data and verify the mac/signature.

**Warning**
This example is only for demonstration purpose. Maintaining and
provisioning the keys/files should be done in a secure way.

In detail, this demo will do following:

- The AES Keys 1 are assumed to be default one (AES-128 of all
  \'0\') and this demo will change it. The new key values
  (KeyID.SDMMetaReadKey and KeyID.SDMFileReadKey) are defined in
  `demos/nx/sdm/ex_sdm_common.h`
- Set ECC key 2 with private key with `EX_SSS_SDM_ECC_PRIVATE_KEY`
  in `demos/nx/sdm/ex_sdm_provision/ex_sdm_provision.h`
- Change file 2 setting
    1. Enable Secure Dynamic Messaging and Mirroring
    2. Disable Deferred Configuration
    3. Enable VCUID mirroring
    4. Enable SDMReadCtr mirroring
    5. Disable SDMReadCtrLimit
    6. Enable SDM File Data Encryption with AppKey 1 (`EX_SSS_SDM_AES_KEY_ID`)
    7. Enable GPIO Status mirroring.
    8. Encrypt PICCData mirroring with AppKey 1 (`EX_SSS_SDM_AES_KEY_ID`)
    9. Enable SDM File Data Sign with ECC Key 2 (`EX_SSS_SDM_ECC_KEY_ID`) or
    10. Enable SDM File Data with MAC (`Nx_SDMFileRead_AccessCondition_No_SDM`)
    11. Access condition for Cmd.GetFileCounters is 0.
    12. SDM input data for signature start at offset 0x10 (`EX_SSS_SDM_SDMMACInputOffset`)
    13. PICCData is mapped to offset 0x20 (`EX_SSS_SDM_PICCDATA_OFFSET`)
    14. SDM encrypted data start at offset 0x60 (`EX_SSS_SDM_SDMENCOffset`) with length 0x20 (`EX_SSS_SDM_SDMENCLength`)
    15. GPIO Status is mapped to offset 0x68 (`EX_SSS_SDM_GPIOStatusOffset`)
    16. SDM signature start at offset 0x80 (`EX_SSS_SDM_SDMMACOffset`) or
    17. SDM mac start at offset 0x80 (`EX_SSS_SDM_SDMMACOffset`)

## Building the Demo

- Build NX middleware stack. Refer [**Linux build**](../../../../doc/linux/readme.md).

  - project - `ex_sdm_provision`

## Running the Example

```
./ex_sdm_provision
```

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :Set AES Key 1.
App   :INFO :Set ECC Private Key 2.
App   :INFO :Change File 2 Setting.
App   :INFO :SDM Enable: 1
App   :INFO :Defer Enable: 0
App   :INFO :VCUID Enable: 1
App   :INFO :SDMReadCtr Enable: 1
App   :INFO :SDMReadCtrLimit Enable: 0
App   :INFO :SDMENCFileData Enable: 1
App   :INFO :GPIOStatus Enable: 1
App   :INFO :SDMMetaRead: 0x1
App   :INFO :SDMFileRead: 0x1
App   :INFO :SDMFileRead2: 0x2
App   :INFO :SDMCtrRet: 0x0
App   :INFO :VCUIDOffset: 0x10
App   :INFO :SDMReadCtrOffset: 0x40
App   :INFO :PICCDataOffset: 0x20
App   :INFO :GPIOStatusOffset: 0x68
App   :INFO :SDMMACInputOffset: 0x10
App   :INFO :SDMENCOffset: 0x60
App   :INFO :SDMENCLength: 0x20
App   :INFO :SDMMACOffset: 0x80
App   :INFO :SDMReadCtrLimit: 0x0
App   :INFO :Defer SDM Encryption Enable: 0
App   :INFO :Defer Method: 0x0
App   :INFO :SDM File Setting Example Success !!!...
App   :INFO :ex_sss Finished
```
