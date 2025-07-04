# PKCS#11 Plugin

PKCS#11(v2.40) is a Public-Key Cryptography Standard for cryptographic
data manipulation. It is mainly used with Hardware Security Modules and
smart cards.

PKCS#11 standalone library is supported with NX for Linux based
platforms.

## PKCS#11 Label Handling

PKCS#11 library calculates keyId through `pkcs11_label_to_keyId`:

1.  CKA_LABEL starts with `sss:`  
    - Based on the most significant nibble keyID is being handled.  
      - `sss:0x1xxxxxxx` EC keyID (0x00 to 0x04)
      - `sss:0x2xxxxxxx` Cert keyID (0x00 to 0x1F)
      - `sss:0x4xxxxxxx` Symm keyID (0x10 to 0x17)

    - keyID is generated by interpreting following string as hex value
      of the keyID. Example - If CKA_LABEL is `sss:0x10000001`, keyID is
      0x01

    >**Note:**  0x1 to 0x3 is reserved keyIDs for certificate and cannot be used.

## PKCS#11 specifications

*Token Label*  
*SSS_PKCS11*

*Pin*  
Not required

*Supported Mechanisms*  
- Digest Mechanisms  
  - CKM_SHA256
  - CKM_SHA384

- ECDSA Mechanisms  
  - CKM_ECDSA
  - CKM_ECDSA_SHA256

- Key Generation Mechanisms  
  - CKM_EC_KEY_PAIR_GEN
  - CKM_AES_KEY_GEN

- AES Mechanisms  
  - CKM_AES_ECB
  - CKM_AES_CBC

- HMAC Mechanisms  
  - CKM_SHA256_HMAC

*Supported API*  
- General-purpose functions  
  - C_Initialize
  - C_Finalize
  - C_GetInfo
  - C_GetFunctionList

- Slot and token management functions  
  - C_GetSlotList
  - C_GetSlotInfo
  - C_GetTokenInfo
  - C_GetMechanismList
  - C_GetMechanismInfo

- Session management functions  
  - C_OpenSession
  - C_CloseSession
  - C_GetSessionInfo
  - C_Login
  - C_Logout

- Object management functions  
  - C_CreateObject
  - C_DestroyObject
  - C_GetAttributeValue
  - C_FindObjectsInit
  - C_FindObjects
  - C_FindObjectsFinal

- Encryption functions  
  - C_EncryptInit
  - C_Encrypt

- Decryption functions  
  - C_DecryptInit
  - C_Decrypt

- Message digesting functions  
  - C_DigestInit
  - C_Digest
  - C_DigestUpdate
  - C_DigestFinal

- Signing and MACing functions  
  - C_SignInit
  - C_Sign
  - C_SignUpdate
  - C_SignFinal
  - C_VerifyInit
  - C_Verify
  - C_VerifyUpdate
  - C_VerifyFinal

- Key management functions  
  - C_GenerateKey
  - C_GenerateKeyPair

- Random number generation functions  
  - C_SeedRandom
  - C_GenerateRandom

## Building on Linux / Raspberry-Pi 4

PKCS#11 standalone shared library can be built on Linux / RaspberryPi
platforms.

Build PKCS#11 library for Raspberry pi 4 with the following CMake
configurations:

- `-DNXMW_RTOS=Default`
- `-DNXMW_HostCrypto=MBEDTLS` / `-DNXMW_HostCrypto=OPENSSL`
- Project: `sss_pkcs11`

>**Note:** While using PKCS#11 as a library on multi threaded systems, the application must ensure proper locking is used. Calling multiple APIs from the library from different threads without proper locks can lead to unexpected behavior.

## Using with pkcs11-tool

Install `pkcs11-tool` by running:

``` shell
sudo apt-get install opensc-pkcs11

Note: Tested with OpenSC 0.24.0 version
```

Set environment variable to the installed PKCS#11 shared library:

``` shell
export PKCS11_MODULE=<NX_MW_PATH>/nxmw/plugin/pkcs11/bin/libsss_pkcs11.so
```

Generating new keypair:

``` shell
pkcs11-tool --module $PKCS11_MODULE --keypairgen --key-type EC:prime256v1 --label "sss:0x10000002"
```

Signing:

``` shell
pkcs11-tool --module $PKCS11_MODULE --sign --id 10000002 -m ECDSA --input-file data.txt --output-file signature.sign
```

Hashing:

``` shell
pkcs11-tool --module $PKCS11_MODULE --hash -m SHA256 --input-file in.der --input-file hash.der
```