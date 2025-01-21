# NX Personalization Example

This project is used to provision keys / certificates for NX Secure Authenticator.
These keys and certificates are used to setup Sigma-I authentication.

It must be noted that by this demo, the default symmetric keys are kept untouched. For actual
deployment, customer should also provision the symmetric keys, or disable the symmetric
authentication.

Provisioning for symmetric authentication is done by ex_update_key or
ex_diversify_key_perso, explained in `ex-sss-update-key` and `diversify-key-perso`

The example will provision the below keys / certificates

- Write CA root public key
- Create certificate repository
- Write the device leaf key pair and device leaf certificate chain
- Write device certificate template and mapping table
- Activate the certificate repository

**On Windows or Linux Hosts, the example will look for the certificates/keypair in following priority**

- Folder indicated by ENV variable \"NX_AUTH_CERT_DIR\"
- Folder : "C:\\nxp\\configuration\\cert_depth3_x509_rev1\\\"(Windows) OR "/tmp/configuration/cert_depth3_x509_rev1/" (Linux)

Hard coded certificates defined in `nx-mw-top/demos/nx/nx_Personalization/nx_Personalization.h`

**MCUs**

Hard coded certificates defined in `nx-mw-top/demos/nx/nx_Personalization/nx_Personalization.h`

```
**IMPORTANT**

The hard-coded certificates and related private keys are being stored in
plain text for demonstration purposes only. During actual product
deployment, customer has to adopt secure means as per their security
needs (note that the potential issue is more with the private keys than
certificates).
```

## Building the example

- Build NX middleware stack. Refer [**Linux build**](../../../doc/linux/readme.md).
	- Project - `nx_Personalization`
	- Make sure to select "NXMW_Auth=SYMM_Auth\" in cmake options.

NXMW_Secure_Tunneling should be selected according to the provisioned symmetric key (Refer `ex-sss-update-key`).
It can be "NXMW_Secure_Tunneling=NTAG_AES128_EV2\" or "NXMW_Secure_Tunneling=NTAG_AES256_EV2\".

By default, the symmetric key would be AES-128 all zeros.

## How to use

Run the tool as:

```
./nx_Personalization -c [{bp|nistp}] -m [AC bitmap] [port_name]

Default options:
- curve : "bp" (brainpool256)
- AC Bitmap : 0x3FFFF
- port_name : depending on the NXMW_SMCOM CMake option (COM7 | /dev/ttyACM0)
```

Note that all the parameters are optional here. If no parameter is
supplied, it will take the default options as mentioned above.
