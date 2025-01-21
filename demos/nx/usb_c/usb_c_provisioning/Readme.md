# Universal Serial Bus Type-C (USB-C) Provisioning demo

This project is used to provision USB-C credentials (ECDSA Key pair and
Device certificate chain) inside the Secure Authenticator.

This example is only for demonstration purpose. Maintaining and
provisioning the credentials should be done in a secure way.

The user should update the credentials `usb_c_ec_priv_key` and
`usb_c_certificate_chain` in
`demos/nx/usb_c/usb_c_provisioning/usb_c_credentials.c`

By default the demo will provision the credentials for Slot ID 0. The
user can update the macro `USB_C_PROVISIONING_SLOT_ID` in
`demos/nx/usb_c/usb_c_provisioning/usb_c_provisioning.h` to provision for a different slot:


## Build project:

- Build NX middleware stack. Refer [**Linux build**](../../../../doc/linux/readme.md).
	-   Project: `usb_c_provisioning`

## Running the Example

```
./usb_c_provisioning
```
