# Cloud Provisioning

This project provisions the client key at location 0x10000003 which
is treated as keyid 0x03 and client certificate at location 0x20000005
which is keyid 0x05. Most Significant nibble Mask is used to distinguish
between keyids.

>**Note:** For the user to provision their client key and certificate update `client_key` and `client_cer` in the file `nxmw/demos/ksdk/provisioning/provisioning_aws.c`

>**Note:** If different KeyID has to be used, Update the SSS_CERTIFICATE_INDEX_CLIENT and SSS_KEYPAIR_INDEX_CLIENT_PRIVATE in the file `nxmw/boards/ksdk/common/aws_iot_config.h`

## Building the example

- Build NX middleware stack. Refer `Create Build files` section in [**MCU_cmake build**](../../../doc/mcu_cmake/readme.md).

      - Project : `cloud_provisioning_aws`

## Console output

If everything is successful, the output will be similar to:
```
nx_mw :INFO :NX_PKG_v02.05.00_20250411
nx_mw :INFO :sss_ex_rtos_task Started.
nx_mw :INFO :cip (Len=22)
                01 04 63 07     00 93 02 08     00 02 03 E8     00 01 00 64
                04 03 E8 00     FE 00
nx_mw :INFO :Session Open Succeed
nx_mw :WARN :No Policy passed. Use default policy.
nx_mw :INFO :Certificate Data File already exist !!!
nx_mw :INFO : PROVISIONING SUCCESSFUL!!!
nx_mw :INFO :Provisioning Example Finished
nx_mw :INFO :ex_sss Finished
```
