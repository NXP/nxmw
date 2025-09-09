# SDM File Read piccdata and verify ECC signature

This project is used to demonstrate the SDM for reading file data, decryption and signature verification. In detail:

-   Read application leaf certificate using cmd.nx_ReadCertRepo_Cert with authentication and parse the public key from
    the certificate
-   Session open with plain communication mode
-   Read out data from file 2, read only length bytes of ndef file
-   Read out data from file 2, read complete ndef data
-   extract VCUID and SDM Read Counter
-   Verify signature
-   close session

## Pre-requisites

-   `ex_sdm_prov_uid_rctr_sig` should run first. It will update the ECC key policy and change file setting for SDM.

## Building the Demo

- Build NX middleware stack. Refer [**Linux build**](../../../../doc/linux/readme.md).

  - Select CMake options:
    - `NXMW_All_Auth_Code=Enabled`
    - `NXMW_Auth=SYMM_Auth`
    - `NXMW_Auth_Symm_App_Key_Id=0`
    - `NXMW_SA_Type=NTAG_X_DNA`

  - Project - `ex_sdm_ver_uid_rctr_sig`

## Running the Example

```
./ex_sdm_ver_uid_rctr_sig
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
nx_mw :WARN :mbedtls_entropy_func_3_X is a dummy implementation with hardcoded entropy. Mandatory to port it to the Micro Controller being used.
nx_mw :INFO :SDM verification.
nx_mw :INFO :Read NDEF File (Length bytes only) (Len=2)
                00 B3
nx_mw :INFO :Read NDEF File (Rest of bytes) (Len=179)
                D1 01 AF 55     04 6E 74 61     67 2E 6E 78     70 2E 63 6F
                6D 2F 78 64     6E 61 3F 6D     3D 30 34 32     36 30 34 37
                31 43 38 38     39 39 30 26     63 3D 30 30     30 30 45 32
                26 73 3D 33     35 31 37 36     37 46 38 32     43 42 39 36
                42 34 31 33     45 38 38 35     46 33 46 32     45 33 33 39
                46 44 43 39     33 32 46 32     30 42 31 45     43 34 41 36
                32 46 33 46     38 42 30 43     43 35 45 42     45 33 34 45
                41 41 35 35     35 45 30 34     33 46 41 30     44 32 35 46
                46 32 35 31     34 35 35 31     37 33 41 42     32 37 31 31
                38 46 35 37     42 45 38 39     41 38 35 45     38 41 36 33
                37 34 44 32     43 30 31 36     31 46 38 31     44 34 38 44
                34 39 34
nx_mw :INFO :NDEF URL Untag.nxp.com/xdna?m=04260471C88990&c=0000E2&s=351767F82CB96B413E885F3F2E339FDC932F20B1EC4A62F3F8B0CC5EBE34EAA555E043FA0D25FF251455173AB27118F57BE89A85E8A6374D2C0161F81D48D494

nx_mw :INFO :plain VCUID  (Len=7)
                04 26 04 71     C8 89 90
nx_mw :INFO :SDMRead Counter 0x0000E2.
nx_mw :INFO :Verify Signature @0x35(Length 0x80) with data @0x1b(Length 0x1a))
nx_mw :INFO :Verify with ECC public key
nx_mw :INFO :Signature in ASN.1: (Len=70)
                30 44 02 20     35 17 67 F8     2C B9 6B 41     3E 88 5F 3F
                2E 33 9F DC     93 2F 20 B1     EC 4A 62 F3     F8 B0 CC 5E
                BE 34 EA A5     02 20 55 E0     43 FA 0D 25     FF 25 14 55
                17 3A B2 71     18 F5 7B E8     9A 85 E8 A6     37 4D 2C 01
                61 F8 1D 48     D4 94
nx_mw :INFO :Verify signature passed.
nx_mw :INFO :ex_sdm_ver_uid_rctr_sig Example Success !!!...
nx_mw :INFO :ex_sss Finished
```