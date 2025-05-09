# Diversification key perso Example

This project demonstrates diversification key personalization using SSS APIs.

Refer [**Diversify Key Perso Example**](./diversify_key_perso.c)

## About the Example

This example derives the diversification key from master key and input parameters on host
and injects the new key into Secure Authenticator.

The input parameter and master key can be set according to MCU type.

**MCU without file system**
1. Update the diversification key input parameters using macros
        EX_DIVERSIFY_INPUT_UID
        EX_DIVERSIFY_INPUT_AID
        EX_DIVERSIFY_INPUT_SID

**Refer**: `nxmw/lib/sss/ex/inc/ex_sss_nx_auth.h`

2. Update the master key using macro with `NXMW_Auth=SYMM_Auth`.
    case1 16-byte master key: EX_SYMM_AUTH_AES128_KEY
    case2 32-byte master key: EX_SYMM_AUTH_AES256_KEY

3. Update the master key using macro with
    `NXMW_Auth=SIGMA_I_Verifier` or `NXMW_Auth=SIGMA_I_Prover`.
    case1 16-byte master key:
        Define EX_SIGMA_I_AUTH_DEFAULT_AESKEY as EX_SYMM_AUTH_AES128_KEY Define
               EX_SIGMA_I_AUTH_DEFAULT_AESKEY_LEN as EX_SYMM_AUTH_AES128_KEY_SIZE
    case2 32-byte master key:
        Define EX_SIGMA_I_AUTH_DEFAULT_AESKEY as EX_SYMM_AUTH_AES256_KEY Define
               EX_SIGMA_I_AUTH_DEFAULT_AESKEY_LEN as EX_SYMM_AUTH_AES256_KEY_SIZE

**Refer** -  `nxmw/lib/sss/ex/inc/ex_sss_nx_auth.h`

**MCU with file system**
1. Update the diversification key input parameters in configuration file.
    UID 00010203040506
    AID 3042F5
    SID 4E585020416275

    **Refer** - `nxmw/binaries/configuration/diversify_key_inputs/plain_dkey_input.txt`

2. Update the master key in configuration file.

    case1 16-byte master key : APPKEY 00000000000000000000000000000000
    case2 32-byte master key : APPKEY 0000000000000000000000000000000000000000000000000000000000000000

    **Refer** - `nxmw/binaries/configuration/symmetric_keys/plain_appkey.txt`

To inject the newly generated key (keyID1), old key value is also
required. Old key value is defined as MACRO

-   case1 16-byte aes old key: EX_AES128_KEYID_1_OLD_KEY
-   case2 32-byte aes old key: EX_AES256_KEYID_1_OLD_KEY

    **Refer** - `nxmw/lib/sss/ex/inc/ex_sss_nx_auth.h`

>**Note:** This example implements the master key diversification in the host MCU for demonstration purposes. In real life use cases, depending on the security requirements of the system, master key storage and diversification should be done in a Secure Authenticator.

Construct diversification input as per AN10922.pdf and use host crypto library to get derived diversification key.

After generating the diversification key on host, this demo will setup Sigma-I/symmetric authentication session to inject diversification key into SE with KeyID 1. To build this project, use cmake option `NXMW_Auth_Symm_Diversify=Disabled` so that master key is used for authentication.

It uses the following APIs and data types:
    `sss_key_object_init()`
    `sss_key_object_allocate_handle()`
    `sss_key_store_set_key()`
    `sss_key_object_free()`
    `sss_mac_context_init()`
    `sss_mac_one_go()`

## Building the Example


- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

  - Select CMake options:
    - `NXMW_Auth_Symm_Diversify=Disabled`
    - `NXMW_Auth=SIGMA_I_Verifier` or `NXMW_Auth=SIGMA_I_Prover` or `NXMW_Auth=SYMM_Auth`
    - `NXMW_Auth_Symm_App_Key_Id=0`
  - Project:`ex_diversify_key_perso`


## Apply key diversification with symmetric authentication

After running this example, diversification key can be used for symmetric authentication which is used in other examples (e.g. nx_Minimal).

- Diversified key is used for symmetric authentication by `NXMW_Auth_Symm_Diversify=Enabled` in cmake options.


Build and run nx_Minimal example with cmake options.

  - `NXMW_Auth_Symm_Diversify=Enabled`
  - `NXMW_Auth=SYMM_Auth`
  - `NXMW_Auth_Symm_App_Key_Id=1`

## Console output

If everything is successful, the output will be similar to:

```
sss   :INFO :Session Open Succeed
App   :WARN :get inputs to derive dkey from:'C:\nxp\configuration\plain_dkey_input.txt' (FILE=C:\nxp\configuration\plain_dkey_input.txt)
App   :INFO :uid (Len=7)
      00 01 02 03    04 05 06
App   :INFO :aid (Len=3)
      30 42 F5
App   :INFO :sid (Len=7)
      4E 58 50 20    41 62 75
App   :WARN :Using appkeys from:'C:\nxp\configuration\plain_appkey.txt' (FILE=C:\nxp\configuration\plain_appkey.txt)
App   :INFO :masterKey (Len=16)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
App   :INFO :diversifyKey (Len=16)
      76 92 01 0C    DA C5 22 63    FF 38 26 25    12 2E 48 3E
App   :INFO :successfully set diversifyKey into Nx
App   :INFO :ex_diversify_key_perso Example Success !!!...
App   :INFO :ex_sss Finished
```

