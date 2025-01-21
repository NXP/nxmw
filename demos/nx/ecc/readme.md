# ECC Example

This project demonstrates Elliptic Curve Cryptography sign and verify operations using SSS APIs.
The example will create a NIST P-256 key at location - **0x02**, with following policy

```
.freezeKUCLimit  = 0,
.cardUnilateralEnabled = 0,
.sdmEnabled      = 1,
.sigmaiEnabled   = 0,
.ecdhEnabled     = 0,
.eccSignEnabled  = 1,
.writeCommMode   = kCommMode_SSS_Full,
.writeAccessCond = Nx_AccessCondition_Auth_Required_0x0,
.kucLimit        = 0,
.userCommMode    = kCommMode_SSS_NA,
```

`userCommMode` is the communication mode provided by user. If it is valid, then
Cmd.ManageKeypair will use it as commMode. Otherwise (when it is kCommMode_SSS_NA),
MW will try to get commMode using Cmd.GetConfiguration.

The key will be used to sign and verify the data (digest). As the Secure Authenticator
does not store the public part of the generated key pair (in this case, at location 0x002),
this demo shows how one can extract and store that public key in a DER file
(for the file system based hosts like Windows/RPi/Linux).

Refer [**ECC Example**](./ex_sss_ecc.c)

## About the Example

This example signs a digest data and verifies the generated signature.

It uses the following APIs and data types:

- `sss_asymmetric_context_init()`
- `kAlgorithm_SSS_SHA256` from :cpp`sss_algorithm_t`
- `kMode_SSS_Sign` from :cpp`sss_mode_t`
- `sss_asymmetric_sign_digest()`
- `kMode_SSS_Verify` from :cpp`sss_mode_t`
- `sss_asymmetric_verify_digest()`

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
      - Project : `ex_ecc`

The access condition of the authentication should match access condition
configuration for Cmd.CryptoRequest and Cmd.ManageKeyPair which can be
configured through Cmd.SetConfiguration Option 0x12 and 0x15.

## Console output

If everything is successful, the output will be similar to:
```
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :Running Elliptic Curve Cryptography Example ex_sss_ecc.c
nx_mw :INFO :Storing the generated public key in public_key.der (in the directory where this demo is run from.)
nx_mw :INFO :Do Signing
nx_mw :INFO :digest (Len=32)
      01 02 03 04    05 06 07 08    09 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
nx_mw :INFO :signature (Len=71)
      30 45 02 20    36 F6 12 62    EE 93 7A A7    DD DC AC A5
      1C 84 BE 9A    F9 C5 73 5F    88 74 D4 9E    2E B9 B7 A1
      BC E1 CE A9    02 21 00 D9    8F E7 8B 43    67 D2 F6 BA
      FE 47 83 BE    20 9A EF 40    39 E2 4E 8A    3B 4B CC 21
      E8 BA 11 86    B6 FC 45
nx_mw :INFO :Signing Successful !!!
nx_mw :INFO :Do Verification
nx_mw :INFO :digest (Len=32)
      01 02 03 04    05 06 07 08    09 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
nx_mw :INFO :signature (Len=71)
      30 45 02 20    36 F6 12 62    EE 93 7A A7    DD DC AC A5
      1C 84 BE 9A    F9 C5 73 5F    88 74 D4 9E    2E B9 B7 A1
      BC E1 CE A9    02 21 00 D9    8F E7 8B 43    67 D2 F6 BA
      FE 47 83 BE    20 9A EF 40    39 E2 4E 8A    3B 4B CC 21
      E8 BA 11 86    B6 FC 45
nx_mw :INFO :Verification Successful !!!
nx_mw :INFO :ex_sss_ecc Example Success !!!...
nx_mw :INFO :ex_sss Finished

```
