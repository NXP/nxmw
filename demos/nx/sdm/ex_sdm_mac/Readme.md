# Secure Dynamic Messaging (SDM) File Reading Demo verify MAC

The Secure Dynamic Messaging (SDM) allows for confidential and integrity
protected data exchange, without requiring a preceding authentication.

This project is used to demonstrate the SDM for reading file data, decryption and mac verification. In detail:

- Read out data from file 2.
- Decrypt PICCData and get VCUID and SDMCtr
- Host should maintain a SDM counter (SDMCtr) which will be used
  in decryption. This demo is assumed to run after
  `ex_sdm_provision`. So the SDMCtr should start with 0. If that
  is not the case, readout counter will be different from host
  SDMCtr and the readout value will be used. *This overwrite
  operation is only for demo purpose and should not be done in
  real case.*
- Generate session keys from KeyID.SDMFileReadKey
  (`EX_SSS_SDM_FILE_READ_AES_KEY`), VCUID and SDMCtr.
- Decrypt file data and output GPIO status
- Verify mac
- Read out data from file 2 again. SDMCtr will not increase
  because it targets the same file.
- Decrypt file data
- Verify mac
- Get free memory
- Read out data from file 2 for 3rd time. SDMCtr will increase by
  1 because there is an different command (Cmd.FreeMem) before
  Cmd.ReadData
- Decrypt file data
- Verify mac

## Pre-requisites

- set EX_SSS_ENABLE_SDM_ECC_SIGNATURE 0 in file ex_sdm_provision.c and build `ex_sdm_provision`
- `ex_sdm_provision` should run first. It will set change file setting for SDM.


## Building the Demo

- Build NX middleware stack. Refer [**Linux build**](../../../../doc/linux/readme.md).

  - Project - `ex_sdm_mac`
  - Select NXMW_Auth to None


## Running the Example

```
./ex_sdm_mac
```


## Console output

If everything is successful, the output will be similar to:
```
nx_mw :WARN :Communication channel is Plain.
nx_mw :WARN :!!!Security and privacy must be assessed.!!!
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Note: The demo is supposed to be run after Cmd.ChangeFileSettings. So SDMReadCtr is reset to 0x000000!
nx_mw :INFO :Read NDEF File (Len=256)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      32 45 31 43    45 36 46 44    35 46 37 39    42 32 45 31
      37 35 41 33    44 30 41 43    43 37 33 30    46 36 30 44
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      36 42 41 46    43 42 41 36    35 36 45 45    30 37 41 37
      42 42 35 34    39 39 42 33    31 31 37 46    38 34 30 46
      34 31 39 46    39 43 31 38    34 31 34 46    33 45 32 37
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
nx_mw :INFO :Decrypt Encrypted PICCData @0x20 (Length 0x20)
nx_mw :INFO :Decrypted PICC data in HEX (Len=16)
      C7 00 01 02    03 04 05 06    01 00 00 8F    32 7D 4F 5B
nx_mw :INFO :Get SDMCtr from PICCData 0x1. It's same to the SDMCtr stored on host
nx_mw :INFO :Get VCUID from PICCData. (Len=7)
      00 01 02 03    04 05 06
nx_mw :INFO :Decrypt SDMENCFileData @0x60 (Length 0x20)
nx_mw :INFO :Decrypted file data (Len=16)
      00 00 00 00    00 00 00 00    49 49 49 00    00 00 00 00
nx_mw :INFO :GPIO Status @0x68: 0x49-0x49-0x49
nx_mw :INFO :Verify SDM Mac @0x80(Length 0x10) with data @0x10(Length 0x70))
nx_mw :INFO :MAC verification passed
nx_mw :INFO :Read NDEF File Again (Len=256)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      32 45 31 43    45 36 46 44    35 46 37 39    42 32 45 31
      37 35 41 33    44 30 41 43    43 37 33 30    46 36 30 44
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      36 42 41 46    43 42 41 36    35 36 45 45    30 37 41 37
      42 42 35 34    39 39 42 33    31 31 37 46    38 34 30 46
      34 31 39 46    39 43 31 38    34 31 34 46    33 45 32 37
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
nx_mw :INFO :Current SDMCtr 0x1
nx_mw :INFO :Decrypt SDMENCFileData @0x60 (Length 0x20)
nx_mw :INFO :Decrypted file data (Len=16)
      00 00 00 00    00 00 00 00    49 49 49 00    00 00 00 00
nx_mw :INFO :Verify SDM Mac @0x80(Length 0x10) with data @0x10(Length 0x70))
nx_mw :INFO :MAC verification passed
nx_mw :INFO :Get Free Memory
nx_mw :INFO :session_ctx->authType 0
nx_mw :INFO :Read NDEF File for 3rd time (Len=256)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      34 36 39 44    31 30 43 37    31 31 44 44    31 33 43 42
      41 33 39 38    39 32 46 38    35 45 31 36    42 39 45 33
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      46 35 36 42    34 33 39 37    37 43 36 42    42 35 31 34
      34 45 39 31    30 37 39 33    39 36 45 45    34 36 31 32
      38 38 45 45    41 36 44 46    35 37 37 45    36 37 38 32
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
nx_mw :INFO :Current SDMCtr 0x2
nx_mw :INFO :Decrypt SDMENCFileData @0x60 (Length 0x20)
nx_mw :INFO :Decrypted file data (Len=16)
      00 00 00 00    00 00 00 00    49 49 49 00    00 00 00 00
nx_mw :INFO :Verify SDM Mac @0x80(Length 0x10) with data @0x10(Length 0x70))
nx_mw :INFO :MAC verification passed
nx_mw :INFO :SDM File Verify Example Success !!!...
nx_mw :INFO :ex_sss Finished
```
