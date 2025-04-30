# ECC Standalone Example

The example demonstrates the use of SSS APIs to open the session to secure authenticator. (Unlike other
examples where the ex_common code is used for session open).
The example will do board init of MCU and establish symmetric auth session with secure authenticator and
perform ECDSA sign / verify crypto operations.
 
**Refer** [**ex_ecc_standalone**](./ex_sss_ecc_standalone.c)

## Prerequisites
• Build NX middleware stack. **Refer** [**MW stack**](../../../doc/stack/readme.md)

## Building the example 
   **Refer** [**MCU Project Build**](../../../doc/mcu_projects/readme.md)

• Project: ecc_standalone

## Console output
If everything is successful, the output will be similar to:

```
nx_mw:Session Open Succeed
nx_mw:Running Elliptic Curve Cryptography Example ex_sss_ecc.c
nx_mw:Do Signing
nx_mw:INFO (Len=361620)
     1 2 3 4 5 6 7 8 9 0 0 0 0 0 0 0
     0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
nx_mw:INFO (Len=361628)
     30 44 2 20 1C 89 D7 AD 5D E7 AF 2A D8 22 5 B2
     77 3 21 A 37 3C 1F 42 B4 75 14 57 7D 28 36 91
     B6 A0 1B 4A 2 20 1C 5B 13 7A AF C8 4A 31 3C B8
     66 E C6 7E AD FF 4A 28 72 92 34 3C 7E 6A F4 AE
     29 20 21 64 B2 D
nx_mw:Signing Successful !!!
nx_mw:Do Verification
nx_mw:INFO (Len=361620)
     1 2 3 4 5 6 7 8 9 0 0 0 0 0 0 0
     0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
nx_mw:INFO (Len=361628)
     30 44 2 20 1C 89 D7 AD 5D E7 AF 2A D8 22 5 B2
     77 3 21 A 37 3C 1F 42 B4 75 14 57 7D 28 36 91
     B6 A0 1B 4A 2 20 1C 5B 13 7A AF C8 4A 31 3C B8
     66 E C6 7E AD FF 4A 28 72 92 34 3C 7E 6A F4 AE
     29 20 21 64 B2 D
nx_mw:Verification Successful !!!
nx_mw:ECC-Standalone Example Success !!!...
```