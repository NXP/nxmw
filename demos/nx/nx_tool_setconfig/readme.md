# NX Set Config Tool

This project is used to configure the Nx Secure Authenticator.

Options supported:

1. **gpio1mode**: Set GPIO1 to disabled, input, output, input tag tamper or down-stream power out
2. **gpio2mode**: Set GPIO2 to disabled, input, output or out_nfcpausefile
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
15. **gpio1config**: Set GPIO1 Config Initial state after power-off cycle, enable i2csupport and backpower
16. **gpio2config**: Set GPIO2 Config Initial state after power-off cycle, enable i2csupport and backpower
17. **gpio1padctrlA**: Set gpio1padctrlA to Debounce Filter value 2 MS bits
18. **gpio1padctrlB**: Set gpio1padctrlB to Debounce Filter value 8 LS bits
19. **gpio1padctrlC**: Set gpio1padctrlC to Debounce filter input filter selection
20. **gpio1padctrlD**: Set gpio1padctrlD to input configuration, output configuration supply selection
21. **gpio2padctrlA**: Set gpio2padctrlA to Debounce Filter value 2 MS bits
22. **gpio2padctrlB**: Set gpio2padctrlB to Debounce Filter value 8 LS bits
23. **gpio2padctrlC**: Set gpio2padctrlC to Debounce filter input filter selection
24. **gpio2padctrlD**: Set gpio2padctrlD to input configuration, output configuration supply selection
25. **nfcpausefileno**: Set nfcpausefile number
26. **nfcpauseoffset**: Set nfcpause offset
27. **nfcpauselength**: Set nfcpause length


## Prerequisites

- Run with access condition 0 (AppMasterKey)
- For Sigma-I, bit0 in CA root key bitmap should be set.
- For Symm authentication, this demo should compiled with APP_KEY_ID0

## Building the example

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

- Build NX middleware stack for supported MCUs. Refer [**MCUX Cmake build**](../../../doc/mcu_cmake/readme.md).

    - Project - `nx_tool_setconfig`
    - Select NXMW_Auth to SIGMA_I_Verifier or SIGMA_I_Prover or SYMM_Auth
    - NXMW_Secure_Tunneling to NTAG_AES128_EV2 or NTAG_AES256_EV2 or NTAG_AES128_AES256_EV2 (Only with Sigma-I)

## How to use

Run the tool as:

```
./nx_tool_setconfig <option_list> <port_name>
```

option_list is a list of supported configuration options, where at least one option must be supplied. Here is the list of supported options and their values:

- \[-gpio1mode {disabled | input | output | tag | powerout}\]
- \[-gpio2mode {disabled | input | output | out_nfcpausefile}\] 
- \[-gpio1Notif {disabled | auth | nfc}\]
- \[-gpio2Notif {disabled | auth | nfc}\]
- \[-gpioMgmtCM {plain | mac | full}\]
- \[-gpioReadCM {plain | mac | full}\]
- \[-gpioMgmtAC {0x0-0xF}\]
- \[-gpioReadAC {0x0-0xF}\]
- \[-cryptoCM {plain | mac | full}\]
- \[-cryptoAC {0x0-0xF}\]
- \[-keypairCM {plain | mac | full}\]
- \[-keypairAC {0x0-0xF}\]
- \[-caRootKeyCM {plain | mac | full}\]
- \[-caRootKeyAC {0x0-0xF}\]
- \[-gpio1config {gpio1Mode is 0x02 or 0x04 then supported value, 0x00-0x01 | gpio1Mode is 0x04 then supported, 0x00-0x03 }\]
- \[-gpio2config {gpio2Mode is 0x02 or 0x04 then supported value, 0x00-0x01 | gpio1Mode is 0x04 then supported, 0x00-0x03 }\]
- \[-gpio1padctrlA {0x00-0x03}\]
- \[-gpio1padctrlB {0x00-0xFF}\]
- \[-gpio1padctrlC {debounce_enable | debounce_disable | input_unfiltered_50ns | input_unfiltered_10ns | input_zif_50ns | input_zif_10ns}\]
- \[-gpio1padctrlD {input_plain_pullup | input_plain_repeater | input_plain | input_plain_pulldown | input_weak_pullup | input_weak_pulldown_disable_wpdn | input_high_z | input_weak_pulldown_disable_wpd |gpio_low_speed_1 | gpio_low_speed_2 | gpio_high_speed_1 | gpio_high_speed_2 | output_disabled | supply_1v8 | supply_1v1}\]
- \[-gpio2padctrlA {0x00-0x03}\]
- \[-gpio2padctrlB {0x00-0xFF}\]
- \[-gpio2padctrlC {debounce_enable | debounce_disable | input_unfiltered_50ns | input_unfiltered_10ns | input_zif_50ns | input_zif_10ns}\]
- \[-gpio2padctrlD {input_plain_pullup | input_plain_repeater | input_plain | input_plain_pulldown | input_weak_pullup | input_weak_pulldown_disable_wpdn | input_high_z | input_weak_pulldown_disable_wpd | gpio_low_speed_1 | gpio_low_speed_2 | gpio_high_speed_1 | gpio_high_speed_2 | output_disabled | supply_1v8 | supply_1v1}\]
- \[-nfcpausefileno {0x00-0x1F}\]
- \[-nfcpauseoffset {0x000000-0xFFFFFF}\]
- \[-nfcpauselength {0x000000-0xFFFFFF}\]

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
