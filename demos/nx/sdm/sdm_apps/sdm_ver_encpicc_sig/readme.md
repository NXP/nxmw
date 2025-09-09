# SDM File Read decrypt piccdata and verify ECC signature

This project is used to demonstrate the SDM for reading file data, decryption and signature verification. In detail:

-   Read application leaf certificate cmd.nx_ReadCertRepo_Cert authentication and parse the public key from
    the certificate
-   Session open with plain communication mode
-   Read out data from file 2, read only length bytes of ndef file at 0x00
-   Read out data from file 2, read complete ndef data
-   decrypt PICCData and get VCUID
-   Generate session keys from KeyID.SDMFileReadKey (`EX_SSS_SDM_FILE_READ_AES_KEY`), VCUID and SDMCtr.
-   Verify signature

## Pre-requisites

-   `ex_sdm_prov_encpicc_sig` should run first. It will update the ECC key policy and change file setting for SDM.

## Building the Demo

- Build NX middleware stack. Refer [**Linux build**](../../../../doc/linux/readme.md).

  - Select CMake options:
    - `NXMW_All_Auth_Code=Enabled`
    - `NXMW_Auth=SYMM_Auth`
    - `NXMW_Auth_Symm_App_Key_Id=0`
    - `NXMW_SA_Type=NTAG_X_DNA`

  - Project - `ex_sdm_ver_encpicc_sig`

## Running the Example

```
./ex_sdm_ver_encpicc_sig
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
nx_mw :INFO :Public Key from Application certificate:  (Len=65)
                04 A1 7C 02     DA B2 E6 7F     D7 7D B3 B7     C5 95 68 58
                42 0B F4 3D     47 63 2F 89     FA 96 16 92     39 EB A4 26
                15 F1 95 4A     A6 FE 0E 76     39 05 08 61     8C 34 08 A7
                32 C7 C5 2D     0C C0 BF 6E     AC FB FE 00     E9 02 DB 17
                FD
nx_mw :INFO :cip (Len=22)
                01 04 63 07     00 93 02 08     00 02 03 E8     00 01 00 64
                04 03 E8 00     FE 00
nx_mw :WARN :Communication channel is Plain.
nx_mw :WARN :!!!Security and privacy must be assessed.!!!
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Successfully opened Plain-session
nx_mw :WARN :mbedtls_entropy_func_3_X is a dummy implementation with hardcoded entropy. Mandatory to port it to the Micro Controller being used.
nx_mw :INFO :SDM verification.
nx_mw :INFO :Read NDEF File (Length bytes only) (Len=2)
                00 C1
nx_mw :INFO :Read NDEF File (Rest of bytes) (Len=193)
                D1 01 BD 55     04 6E 74 61     67 2E 6E 78     70 2E 63 6F
                6D 2F 78 64     6E 61 3F 76     3D 45 45 26     65 3D 35 38
                30 36 31 36     32 45 39 42     45 31 38 34     33 31 32 43
                34 30 41 43     42 32 35 44     32 36 37 37     39 31 26 73
                3D 32 43 36     45 31 38 39     34 45 38 44     45 30 42 41
                35 31 35 32     34 42 37 39     43 30 35 31     44 33 33 46
                46 30 35 41     30 43 37 38     42 30 44 44     31 43 37 42
                41 41 34 44     35 46 36 35     46 44 31 45     35 35 42 33
                43 44 45 42     30 45 45 43     41 32 30 36     39 41 43 36
                38 34 43 43     35 46 37 37     46 31 43 45     33 46 45 39
                45 34 34 30     44 44 43 32     35 38 43 34     35 41 30 39
                36 30 30 38     34 38 46 39     43 37 39 43     46 32 30 34
                38
nx_mw :INFO :NDEF URL Untag.nxp.com/xdna?v=EE&e=5806162E9BE184312C40ACB25D267791&s=2C6E1894E8DE0BA51524B79C051D33FF05A0C78B0DD1C7BAA4D5F65FD1E55B3CDEB0EECA2069AC684CC5F77F1CE3FE9E440DDC258C45A09600848F9C79CF2048

nx_mw :INFO :Decrypt Encrypted PICCData @0x20 (Length 0x20)
nx_mw :INFO :Decrypted PICC data in HEX (Len=16)
                C7 04 26 04     71 C8 89 90     E0 00 00 54     70 A1 DF E5
nx_mw :INFO :Get UID from PICCData. (Len=7)
                04 26 04 71     C8 89 90
nx_mw :INFO :Verify Signature @0x43(Length 0x80) with data @0x1b(Length 0x28))
nx_mw :INFO :Verify with ECC public key
nx_mw :INFO :Signature in ASN.1: (Len=71)
                30 45 02 20     2C 6E 18 94     E8 DE 0B A5     15 24 B7 9C
                05 1D 33 FF     05 A0 C7 8B     0D D1 C7 BA     A4 D5 F6 5F
                D1 E5 5B 3C     02 21 00 DE     B0 EE CA 20     69 AC 68 4C
                C5 F7 7F 1C     E3 FE 9E 44     0D DC 25 8C     45 A0 96 00
                84 8F 9C 79     CF 20 48
nx_mw :INFO :Verify signature passed.
nx_mw :INFO :ex_sdm_ver_encpicc_sig Example Success !!!...
nx_mw :INFO :ex_sss Finished
```