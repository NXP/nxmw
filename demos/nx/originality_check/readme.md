# Originality Check Example

During manufacturing, NTAGECC is trust-provisioned with an ECC-based key
pair and related certificate to allow verification of the genuineness of
the IC. The originality check is done by executing a card-unilateral
authentication through a challenge-response protocol.

This project demonstrates originality check at PICC level using SSS/Nx APIs. It will do following
- Send random challenge to Secure Authenticator.
- Read originality check certificate.
- Verify Cert.Orig against the Originality CA Public key.
- Verify the signature received from Secure Authenticator with public key from certificate.

The Originality CA Public key is defined by macro
EX_ORIG_CA_PUBLIC_KEY in ex_sss_originality_check.h
User should update it with correct key value.

Refer [**ex_sss_originality_check.c**](./ex_sss_originality_check.c)

## About the Example

This example does an originality check at PICC level by executing a
card-unilateral authentication.

It uses the following APIs and data types:
    `nx_ISOInternalAuthenticate()`
    `nx_ReadData()`
    `sss_asymmetric_context_init()`
    `sss_asymmetric_verify_one_go()`
    `sss_asymmetric_context_free()`

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).

  - Project - `ex_originality_check`
  - Select NXMW_Auth to None
  - NXMW_Secure_Tunneling to None
  - NXMW_NX_Type to NX_PICC

## How to use

Run the tool as:

If you have built a binary, flash the binary on to the board and reset the board.

```
If you have built an *exe* to be run from Windows, run as:

ex_originality_check.exe <PORT NAME>
```

```
On Linux, run as:

./ex_originality_check
```

## Console output

If everything is successful, the output will be similar to:

```
sss   :INFO :Session Open Succeed
App   :INFO :Generate RndA (Len=16)
      C4 F4 F3 4B    46 DB 86 58    9E 9B 04 C3    2F DF 8E 51
App   :INFO :Use OptsA (Len=32)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
App   :INFO :Send Cmd.ISOInternalAuthenticate.
App   :INFO :Rx RndB (Len=16)
      82 49 B5 1A    E7 6A E7 88    A1 14 60 3A    E8 2C 02 1F
App   :INFO :Rx Signature (Len=64)
      A3 F4 A3 A4    AA 3C 29 19    A1 4C EA 08    A5 9B 50 E5
      99 4A 96 B7    52 B5 ED DB    AD FC 97 E8    F9 BF 8D 12
      A1 3C 72 D6    47 EB 7E ED    BB C7 90 B6    A5 0D 3C EF
      41 83 1C 6D    E2 2C 9A BC    EC 45 1B 25    30 29 DE BC
App   :INFO :Read certificate.
App   :INFO :Verify Cert.Orig against the Originality CA Public key Success.
App   :INFO :Get public key from certificate.
App   :INFO :Public key (Len=91)
      30 59 30 13    06 07 2A 86    48 CE 3D 02    01 06 08 2A
      86 48 CE 3D    03 01 07 03    42 00 04 45    2D FB F7 98
      49 29 69 EF    BB 24 B6 58    E6 05 E5 26    71 37 70 F3
      4B E8 7A 57    9E 1C F1 34    79 1A A7 37    1D C8 09 39
      A4 D9 5C 1E    6C 7C 2C 52    D4 7A FF C3    E4 EC 46 28
      23 DB DE BB    AD 1B 28 9F    1D CF 29
App   :INFO :verify Signature Success.
App   :INFO :Originality Check Example Success !!!...
App   :INFO :ex_sss Finished
```
