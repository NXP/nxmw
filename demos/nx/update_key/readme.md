# Update Key Example

This project demonstrates update aes key using sss apis.

## About the Example

This project demonstrates update new aes key operation using sss apis.

-   Update the new aes key use macro \"EX_UPDATE_NEW_AESKEY\".
-   Update the old aes key use macro \"EX_UPDATE_OLD_AESKEY\".
-   Update key ID use macro \"EX_UPDATE_KEY_ID\" (default it\'s 0).

Refer [**Update Key Example code**](./ex_sss_update_key.c)

It uses the following APIs and data types:

    `sss_key_object_init()`
    `sss_key_object_allocate_handle()`
    `sss_key_store_set_key()`
    `sss_key_object_free()`

## Building the Example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).

  - Select CMake options:
    - `NXMW_Auth=SYMM_Auth`
    - `NXMW_Auth_Symm_App_Key_Id=0`
    - `NXMW_Secure_Tunneling=NTAG_AES128_EV2`

  - project - `ex_update_key`

## Apply AES256 key with symmetric authentication

After running this example, AES256 key can be used for symmetric
authentication which is used in other examples (e.g. nx_Minimal).

- AES256 key is used for symmetric authentication by `NXMW_Secure_Tunneling=NTAG_AES256_EV2` in cmake options.

- Host without file system - Update the AES key using macro with `NXMW_Auth=SYMM_Auth`.
    case1 16-byte AES key: EX_SYMM_AUTH_AES128_KEY
    case2 32-byte AES key: EX_SYMM_AUTH_AES256_KEY

    Refer [**nx-mw-top/lib/sss/ex/inc/ex_sss_nx_auth.h**](./../../../lib/sss/ex/inc/ex_sss_nx_auth.h)

- Host with file system. - Update the AES key in configuration file.
    case1 16-byte AES key : APPKEY 00000000000000000000000000000000
    case2 32-byte AES key : APPKEY 0000000000000000000000000000000000000000000000000000000000000000

- Build and run nx_Minimal example with cmake options.
    `NXMW_Auth=SYMM_Auth`
    `NXMW_Auth_Symm_App_Key_Id=0`
    `NXMW_Secure_Tunneling=NTAG_AES256_EV2`


## Console output

If everything is successful, the output will be similar to:

```
sss   :INFO :Session Open Succeed
App   :INFO :Old aes key (Len=16)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
App   :INFO :New aes key (Len=32)
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
      00 00 00 00    00 00 00 00    00 00 00 00    00 00 00 00
App   :INFO :Successfully aes key injected into nx
App   :INFO :ex_sss_update_key Example Success !!!...
App   :INFO :ex_sss Finished
```
