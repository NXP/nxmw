# NX Set Config Tool

This project is used to configure the Nx Secure Authenticator.

Options supported:

1. **gpio1mode**: Set GPIO1 to disabled, input, output, input tag tamper or down-stream power out
2. **gpio2mode**: Set GPIO2 to disabled, input or output
3. **gpio1Notif**: Set GPIO1 notification on authentication. It can be disabled, enabled for authentication or enabled for presence of NFC field
4. **gpio2Notif**: Set GPIO2 notification on authentication. It can be disabled, enabled for authentication or enabled for presence of NFC field
5. **gpioMgmtCM**: Set ManageGPIO communication mode
6. **gpioReadCM**: Set ReadGPIO communication mode
7. **gpioMgmtAC**: Set ManageGPIO access condition
8. **gpioReadAC**: Set ReadGPIO access condition
9. **cryptoCM**: Set Crypto API communication mode
10. **cryptoAC**: Set Crypto API access condition
11. **keypairCM**: Set ManageKeyPair communication mode
12. **keypairAC**: Set ManageKeyPair access condition
13. **caRootKeyCM**: Set ManageCARootKey communication mode
14. **caRootKeyAC**: Set ManageCARootKey access condition

## Prerequisites

- Run with access condition 0 (AppMasterKey)
- For Sigma-I, bit0 in CA root key bitmap should be set.
- For Symm authentication, this demo should compiled with APP_KEY_ID0

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
    - Project - `nx_tool_setconfig`
    - Select NXMW_Auth to SIGMA_I_Verifier or SIGMA_I_Prover or SYMM_Auth
    - NXMW_Secure_Tunneling to NTAG_AES128_EV2 or NTAG_AES128_EV2 or NTAG_AES128_AES256_EV2 (Only with Sigma-I)

## How to use

Run the tool as:

```
./nx_tool_setconfig <option_list> <port_name>
```

option_list is a list of supported configuration options, where at least one option must be supplied. Here is the list of supported options and their values:

- [-gpio1mode {disabledoutputpowerout}]
- [-gpio2mode {disabledoutput}]
- [-gpio1Notif {disablednfc}]
- [-gpio2Notif {disablednfc}]
- [-gpioMgmtCM {plainfull}]
- [-gpioReadCM {plainfull}]
- [-gpioMgmtAC {0x0-0xF}]
- [-gpioReadAC {0x0-0xF}]
- [-cryptoCM {plainfull}]
- [-cryptoAC {0x0-0xF}]
- [-keypairCM {plainfull}]
- [-keypairAC {0x0-0xF}]
- [-caRootKeyCM {plainfull}]
- [-caRootKeyAC {0x0-0xF}]

For example, to set GPIO1 to be in the output mode, following command can be run:

```
./nx_tool_setconfig -gpio1mode output COM7
```

### Console output

If everything is successful, the output will be similar to:
```
sss   :INFO :Session Open Succeed
hostLib:INFO :SET config Example Success !!!...
hostLib:INFO :ex_sss Finished
```

