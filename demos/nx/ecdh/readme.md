# ECDH Example

This project demonstrates generating a ECDH key using SSS APIs on NX
Secure Authenticator.

Refer [**Ecdh Example**](./ex_sss_ecdh.c)

The example will create a key pair in nx Secure Authenticator and will
set a pre-cooked public key on host key store.

The key pair and publicKey key objects will be the inputs for DH derive
key.

The output ecdh keyObject can be created as

-   Option 1 - ecdh key object on host (OpenSSL or MbedTLS) to hold the shared secret data.
-   Option 2 - ecdh key object on nx Secure Authenticator with valid transient / static buffer slot id (cipher type =
    kSSS_CipherType_BufferSlots).
    -   Valid slot numbers:
        -   0x80 - 0x87 (Transient buffer slots. Each slot of 16 bytes.)
        -   0xC0 - 0xCF (Static buffer slots. Each slot of 16 bytes.)

This example includes 4 cases:

1. Use static key-pair (key ID 0x3) and shared secret is output to host key object.
2. Use static key-pair (key ID 0x3) and shared secret is stored in internal transient buffer.
3. Use ephemeral key-pair (Key ID 0xFE for NIST P-256) and shared secret is output to host key object.
4. Use ephemeral key-pair (Key ID 0xFE for NIST P-256) and shared secret is stored in internal transient buffer.

Static key will be created with following policy

```
.freezeKUCLimit        = 0,
.cardUnilateralEnabled = 0,
.sdmEnabled            = 0,
.sigmaiEnabled         = 0,
.ecdhEnabled           = 1,
.eccSignEnabled        = 0,
.writeCommMode         = kCommMode_SSS_Full,
.writeAccessCond       = Nx_AccessCondition_Auth_Required_0x1,
.kucLimit              = 0,
.userCommMode          = kCommMode_SSS_NA,
```

## About the Example

This example generates an ECDH key.

It uses the following APIs and data types:

- `sss_derive_key_context_init()`
- `sss_key_object_init()`
- `sss_key_object_allocate_handle()`
- `sss_derive_key_dh_one_go()`
- `kAlgorithm_SSS_ECDH` from :cpp`sss_algorithm_t`
- `kMode_SSS_ComputeSharedSecret` from :cpp`sss_mode_t`

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
  - Project -  `ex_ecdh`

The access condition of the authentication should match access condition
configuration for Cmd.CryptoRequest and Cmd.ManageKeyPair which can be
configured through Cmd.SetConfiguration Option 0x12 and 0x15.

## Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
App   :INFO :

App   :INFO :ECDH with static keypair. Export shared secrect to keyobject.
App   :INFO :ECDH own Keypair 3
App   :INFO :ECDH peer public Key (Len=91)
      30 59 30 13    06 07 2A 86    48 CE 3D 02    01 06 08 2A
      86 48 CE 3D    03 01 07 03    42 00 04 B0    62 84 30 F3
      42 A0 6A 15    F0 4C 61 EF    B4 47 45 9A    0C 43 D9 A9
      31 4F 09 AA    E6 52 0C 63    C8 63 8F E5    9F 8F A5 03
      4B 4B AB 01    6E 1F 86 6F    06 C4 47 89    E2 8E 49 1A
      AF 63 24 30    BE 40 91 FE    90 98 70
App   :INFO :ECDH successful !!!
App   :INFO :ECDH derive Key (Len=32)
      DA 30 73 7D    12 7F 18 17    C9 F8 47 AF    23 1C 8D 69
      62 06 DD F0    A5 BF AD EF    00 87 0D 23    0A 20 3B 95
App   :INFO :Plain text data:
  (Len=32)
      00 01 02 03    04 05 06 07    08 09 0A 0B    0C 0D 0E 0F
      10 11 12 13    14 15 16 17    18 19 1A 1B    1C 1D 1E 1F
App   :INFO :IV data:
  (Len=16)
      EB F5 22 DE    A7 BB D5 66    B8 F6 85 B7    AD C1 06 AB
App   :INFO :Encrypted data with ECDH derive key:
  (Len=32)
      E9 34 E2 30    A4 0B F6 5B    51 D4 CB CE    BD E8 3C A7
      EB F5 22 DE    A7 BB D5 66    B8 F6 85 B7    AD C1 06 AB
App   :INFO :ex_sss_ecdh Example Success !!!...
App   :INFO :

App   :INFO :ECDH with static keypair. Store shared secrect to internal buffer.
App   :INFO :ECDH own Keypair 4
App   :INFO :ECDH peer public Key (Len=91)
      30 59 30 13    06 07 2A 86    48 CE 3D 02    01 06 08 2A
      86 48 CE 3D    03 01 07 03    42 00 04 B0    62 84 30 F3
      42 A0 6A 15    F0 4C 61 EF    B4 47 45 9A    0C 43 D9 A9
      31 4F 09 AA    E6 52 0C 63    C8 63 8F E5    9F 8F A5 03
      4B 4B AB 01    6E 1F 86 6F    06 C4 47 89    E2 8E 49 1A
      AF 63 24 30    BE 40 91 FE    90 98 70
App   :INFO :ECDH successful !!!
App   :INFO :Plain text data:
  (Len=32)
      00 01 02 03    04 05 06 07    08 09 0A 0B    0C 0D 0E 0F
      10 11 12 13    14 15 16 17    18 19 1A 1B    1C 1D 1E 1F
App   :INFO :IV data:
  (Len=16)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
App   :INFO :Encrypted data with internal derive key :
  (Len=32)
      D5 CE 48 09    68 63 4C 97    3A 10 25 7B    82 3A F9 88
      17 0F CC 5D    08 0A 57 A0    BB BF 9A D2    F2 CE 64 67
App   :INFO :ex_sss_ecdh Example Success !!!...
App   :INFO :

App   :INFO :ECDH with ephemeral keypair. Export shared secrect to keyobject.
sss   :WARN :Keyid's 254 and 255 are used for ephemeral keys.
sss   :WARN :Key is already present at these locations. No new key is created
App   :INFO :ECDH own Keypair 254
App   :INFO :ECDH peer public Key (Len=91)
      30 59 30 13    06 07 2A 86    48 CE 3D 02    01 06 08 2A
      86 48 CE 3D    03 01 07 03    42 00 04 B0    62 84 30 F3
      42 A0 6A 15    F0 4C 61 EF    B4 47 45 9A    0C 43 D9 A9
      31 4F 09 AA    E6 52 0C 63    C8 63 8F E5    9F 8F A5 03
      4B 4B AB 01    6E 1F 86 6F    06 C4 47 89    E2 8E 49 1A
      AF 63 24 30    BE 40 91 FE    90 98 70
App   :INFO :ECDH successful !!!
App   :INFO :ECDH derive Key (Len=32)
      4D 1D D0 6E    EA F1 DC D3    4B 24 2A 1E    BD BB 91 59
      E2 11 CF C9    7F AF E6 A3    68 20 53 CE    25 84 3A 83
App   :INFO :Plain text data:
  (Len=32)
      00 01 02 03    04 05 06 07    08 09 0A 0B    0C 0D 0E 0F
      10 11 12 13    14 15 16 17    18 19 1A 1B    1C 1D 1E 1F
App   :INFO :IV data:
  (Len=16)
      1E 85 AD 3F    49 E3 6A EA    FE 80 83 D1    81 0D 7A BD
App   :INFO :Encrypted data with ECDH derive key:
  (Len=32)
      15 06 2D B4    96 2D 21 49    7D A3 81 1D    B8 A6 4E 89
      1E 85 AD 3F    49 E3 6A EA    FE 80 83 D1    81 0D 7A BD
App   :INFO :ex_sss_ecdh Example Success !!!...
App   :INFO :

App   :INFO :ECDH with ephemeral keypair. Store shared secrect to internal buffer.
sss   :WARN :Keyid's 254 and 255 are used for ephemeral keys.
sss   :WARN :Key is already present at these locations. No new key is created
App   :INFO :ECDH own Keypair 254
App   :INFO :ECDH peer public Key (Len=91)
      30 59 30 13    06 07 2A 86    48 CE 3D 02    01 06 08 2A
      86 48 CE 3D    03 01 07 03    42 00 04 B0    62 84 30 F3
      42 A0 6A 15    F0 4C 61 EF    B4 47 45 9A    0C 43 D9 A9
      31 4F 09 AA    E6 52 0C 63    C8 63 8F E5    9F 8F A5 03
      4B 4B AB 01    6E 1F 86 6F    06 C4 47 89    E2 8E 49 1A
      AF 63 24 30    BE 40 91 FE    90 98 70
App   :INFO :ECDH successful !!!
App   :INFO :Plain text data:
  (Len=32)
      00 01 02 03    04 05 06 07    08 09 0A 0B    0C 0D 0E 0F
      10 11 12 13    14 15 16 17    18 19 1A 1B    1C 1D 1E 1F
App   :INFO :IV data:
  (Len=16)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
App   :INFO :Encrypted data with internal derive key :
  (Len=32)
      E8 09 89 6F    9B F9 3F E8    4A E5 8C 06    C1 96 80 D6
      AC 3B 9D 9A    8B C8 68 57    85 FA A7 EA    40 ED 3B 65
App   :INFO :ex_sss_ecdh Example Success !!!...
App   :INFO :ex_sss Finished

```