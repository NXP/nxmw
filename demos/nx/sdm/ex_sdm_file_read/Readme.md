# Secure Dynamic Messaging (SDM) File Reading Demo and verify ECC signature

The Secure Dynamic Messaging (SDM) allows for confidential and integrity
protected data exchange, without requiring a preceding authentication.

This project is used to demonstrate the SDM for reading file data, decryption and signature verification. In detail:

-   Read out data from file 2.
-   Decrypt PICCData and get VCUID and SDMCtr
-   Host should maintain a SDM counter (SDMCtr) which will be used in decryption.
    This demo is assumed to run after `ex_sdm_provision`. So the SDMCtr should
    start with 0. If that is not the case, readout counter will be different from host
    SDMCtr and the readout value will be used. *This overwrite operation is only for demo
    purpose and should not be done in real case.*
-   Generate session keys from KeyID.SDMFileReadKey (`EX_SSS_SDM_FILE_READ_AES_KEY`), VCUID and SDMCtr.
-   Decrypt file data and output GPIO status
-   Verify signature
-   Read out data from file 2 again. SDMCtr will not increase because it targets the same file.
-   Decrypt file data
-   Verify signature
-   Get free memory
-   Read out data from file 2 for 3rd time. SDMCtr will increase by
    1 because there is an different command (Cmd.FreeMem) before
    Cmd.ReadData
-   Decrypt file data
-   Verify signature


## Pre-requisites

-   set EX_SSS_ENABLE_SDM_ECC_SIGNATURE 1 in file ex_sdm_provision.c and build `ex_sdm_provision`
-   `ex_sdm_provision` should run first. It will initialize the ECC key and change file setting for SDM.

## Building the Demo

- Build NX middleware stack. Refer [**Linux build**](../../../../doc/linux/readme.md).

  - Project - `ex_sdm_file_read`
  - Select NXMW_Auth to None

## Running the Example

```
./ex_sdm_file_read
```

## Console output

If everything is successful, the output will be similar to:

```
nx_mw :WARN :!!!Security and privacy must be assessed.!!!
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Note: The demo is supposed to be run after Cmd.ChangeFileSettings. So SDMReadCtr is reset to 0x000000!
nx_mw :INFO :Read NDEF File (Len=256)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      44 36 45 42    30 46 42 41    38 35 39 39    34 34 45 33
      35 31 31 34    41 38 43 31    33 34 45 37    37 43 37 41
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      37 36 32 38    31 34 46 34    37 44 39 38    32 43 37 34
      39 33 35 46    30 41 34 46    36 41 31 36    36 33 33 32
      39 31 42 43    36 43 32 44    35 46 44 31    38 36 37 38
      41 35 33 34    37 46 36 31    37 39 46 36    36 41 35 39
      46 45 36 45    39 32 35 32    36 43 46 41    45 46 31 32
      39 43 35 45    46 37 41 38    31 43 41 39    39 41 33 39
      33 41 46 30    43 30 44 46    33 38 33 30    39 36 41 44
      43 42 44 45    32 38 35 32    31 37 35 41    43 46 45 46
      42 38 32 31    45 31 41 45    34 33 33 31    39 30 37 37
      31 33 33 33    44 42 44 37    43 34 45 35    34 35 42 45
nx_mw :INFO :Decrypt Encrypted PICCData @0x20 (Length 0x20)
nx_mw :INFO :Decrypted PICC data in HEX (Len=16)
      C7 00 01 02    03 04 05 06    0E 00 00 73    0A 32 08 68
nx_mw :WARN :Readout SDMReadCtr(0xe) is different from host SDMReadCtr(0x1)!
nx_mw :WARN :Overwrite host SDMReadCtr. This is only for demo purpose and should not be done in real case!
nx_mw :INFO :Get VCUID from PICCData. (Len=7)
      00 01 02 03    04 05 06
nx_mw :INFO :Decrypt SDMENCFileData @0x60 (Length 0x20)
nx_mw :INFO :Decrypted file data (Len=16)
      00 00 00 00    00 00 00 00    49 49 49 00    00 00 00 00
nx_mw :INFO :GPIO Status @0x68: 0x49-0x49-0x49
nx_mw :INFO :verify Signature @0x80(Length 0x80) with data @0x10(Length 0x70))
nx_mw :INFO :Verify with ECC public key
nx_mw :INFO :Signature in ASN.1: (Len=71)
      30 45 02 21    00 91 BC 6C    2D 5F D1 86    78 A5 34 7F
      61 79 F6 6A    59 FE 6E 92    52 6C FA EF    12 9C 5E F7
      A8 1C A9 9A    39 02 20 3A    F0 C0 DF 38    30 96 AD CB
      DE 28 52 17    5A CF EF B8    21 E1 AE 43    31 90 77 13
      33 DB D7 C4    E5 45 BE
nx_mw :INFO :Verify signature passed.
nx_mw :INFO :Read NDEF File Again (Len=256)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      44 36 45 42    30 46 42 41    38 35 39 39    34 34 45 33
      35 31 31 34    41 38 43 31    33 34 45 37    37 43 37 41
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      37 36 32 38    31 34 46 34    37 44 39 38    32 43 37 34
      39 33 35 46    30 41 34 46    36 41 31 36    36 33 33 32
      39 31 42 43    36 43 32 44    35 46 44 31    38 36 37 38
      41 35 33 34    37 46 36 31    37 39 46 36    36 41 35 39
      46 45 36 45    39 32 35 32    36 43 46 41    45 46 31 32
      39 43 35 45    46 37 41 38    31 43 41 39    39 41 33 39
      33 41 46 30    43 30 44 46    33 38 33 30    39 36 41 44
      43 42 44 45    32 38 35 32    31 37 35 41    43 46 45 46
      42 38 32 31    45 31 41 45    34 33 33 31    39 30 37 37
      31 33 33 33    44 42 44 37    43 34 45 35    34 35 42 45
nx_mw :INFO :Current SDMCtr 0xe
nx_mw :INFO :Decrypt SDMENCFileData @0x60 (Length 0x20)
nx_mw :INFO :Decrypted file data (Len=16)
      00 00 00 00    00 00 00 00    49 49 49 00    00 00 00 00
nx_mw :INFO :verify Signature @0x80(Length 0x80) with data @0x10(Length 0x70))
nx_mw :INFO :Verify with ECC public key
nx_mw :INFO :Signature in ASN.1: (Len=71)
      30 45 02 21    00 91 BC 6C    2D 5F D1 86    78 A5 34 7F
      61 79 F6 6A    59 FE 6E 92    52 6C FA EF    12 9C 5E F7
      A8 1C A9 9A    39 02 20 3A    F0 C0 DF 38    30 96 AD CB
      DE 28 52 17    5A CF EF B8    21 E1 AE 43    31 90 77 13
      33 DB D7 C4    E5 45 BE
nx_mw :INFO :Verify signature passed.
nx_mw :INFO :Get Free Memory
nx_mw :INFO :session_ctx->authType 0
nx_mw :INFO :Read NDEF File for 3rd time (Len=256)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      45 34 43 38    42 46 31 35    44 46 37 31    41 32 30 35
      38 35 33 46    39 39 39 32    46 30 39 35    46 32 37 44
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      44 32 32 41    35 37 31 44    31 31 35 33    35 42 39 34
      37 39 45 36    38 36 43 38    34 43 41 33    32 45 36 36
      36 39 32 39    36 30 39 31    39 35 36 44    45 30 43 34
      31 46 36 31    38 44 38 46    32 36 37 43    44 46 43 38
      46 39 42 36    46 35 31 34    46 45 35 34    34 43 35 30
      42 38 35 32    42 32 34 37    37 43 34 38    34 44 38 36
      39 30 39 39    42 38 44 31    30 41 32 30    34 38 34 37
      37 32 41 38    38 42 42 32    46 42 36 35    45 37 42 30
      31 38 32 32    43 45 37 34    33 42 37 34    45 42 39 30
      41 38 33 39    38 39 45 37    36 39 44 41    41 33 44 42
nx_mw :INFO :Current SDMCtr 0xf
nx_mw :INFO :Decrypt SDMENCFileData @0x60 (Length 0x20)
nx_mw :INFO :Decrypted file data (Len=16)
      00 00 00 00    00 00 00 00    49 49 49 00    00 00 00 00
nx_mw :INFO :verify Signature @0x80(Length 0x80) with data @0x10(Length 0x70))
nx_mw :INFO :Verify with ECC public key
nx_mw :INFO :Signature in ASN.1: (Len=71)
      30 45 02 20    69 29 60 91    95 6D E0 C4    1F 61 8D 8F
      26 7C DF C8    F9 B6 F5 14    FE 54 4C 50    B8 52 B2 47
      7C 48 4D 86    02 21 00 90    99 B8 D1 0A    20 48 47 72
      A8 8B B2 FB    65 E7 B0 18    22 CE 74 3B    74 EB 90 A8
      39 89 E7 69    DA A3 DB
nx_mw :INFO :Verify signature passed.
nx_mw :INFO :SDM File Verify Example Success !!!...
nx_mw :INFO :ex_sss Finished
```
