# Changelog

## \[v02.07.00\]
- Added FRDM-MCXA156 platform support for select examples.
	- Added standalone MCUXpresso project - nxmw\mcux_project\mcxa156\ex_ecc.
	- Added VCOM support.
- NX CLI tool enhancements
	- Added new command el2go-parser for Windows OS. For details Refer - [**NX CLI Tool**](demos/nx/nx_cli_tool/readme.md)
	- Updated `certrepo-load-cert` command to take input argument either as a folder or a .der/.pem file. For folders, it reads the device UID to locate the certificate, and for files - it loads the certificate directly.
	- Added new command `update-eccpolicy` to update the policies of ECC key in SA.
	- Updated `get-uid` command to write UID to a file as a hex value (separated by semicolon).
	- Added convert_deviceid_json.py python script to convert deviceId from decimal to hex in el2go JSON files.
- Extended `nx_tool_setconfig` example to configure gpio management.
- Extended T=1oI2C cold reset API support with VCOM interface.
- Updated document for dual interface example.
- Fixes for static analysis findings.

## \[v02.06.00\]
- CMSIS Driver support for MCXN947 and MCXA153 platforms added.
- Restructured MCU GPIO APIs - Platform specific gpio apis are now defined in boards files.
- NX CLI tool enhancements
	- New commands added dgst-sha256, dgst-sign, dgst-verify, derive-ecdh. For details refer - [**NX CLI Tool**](demos/nx/nx_cli_tool/readme.md)
	- Added enable and waccess options for genkey command
	- Updated get-uid command to write uid in a file
-  New examples -
	- Mbedtls lwip client Example supports MCUs such as MCXN947. Refer [**mbedtls_3_x_lwip_client example**](demos/nx/mbedtls_3_x_lwip_client/readme.md)
	- Added Secure Dynamic Messaging (SDM) examples for provisioning and verification of NTAG-X-DNA
	- SDM Provisioning - Encrypted PICC with Signature. Refer [**ex_sdm_prov_encpicc_sig example**](demos/nx/sdm/sdm_apps/sdm_prov_encpicc_sig/readme.md)
	- SDM Verification - Encrypted PICC with Signature. Refer [**ex_sdm_ver_encpicc_sig example**](demos/nx/sdm/sdm_apps/sdm_ver_encpicc_sig/readme.md)
	- SDM Provisioning - UID with RCTR and Signature. Refer [**ex_sdm_prov_uid_rctr_sig example**](demos/nx/sdm/sdm_apps/sdm_prov_uid_rctr_sig/readme.md)
	- SDM Verification - UID with RCTR and Signature. Refer [**ex_sdm_ver_encpicc_sig example**](demos/nx/sdm/sdm_apps/sdm_ver_uid_rctr_sig/readme.md)
- ex_t1oi2c Standalone example added for MCXA153. Refer [**ex_t1oi2c example**](lib/hostlib/smCom/T1oI2C/example/linux/readme.md)
- west.yml file of MCU SDK updated to to clone nxp-iot-agent module.
- USB-C Example changed to use authentication key from slot id 1.
- Secure Authenticator APIs Documentation added.
- Fixes for static analysis findings.

## \[v02.05.01\]
- Removed unused module in west.yml file

## \[v02.05.00\]
- Support for Windows, LPC55s69, MCXN947, MCXA153 platforms added.
	- For Windows, refer [**Getting Started on Windows**](doc/windows/readme.md)
	- For MCU Projects, refer [**Getting Started on MCUs Using Standalone MCUXpresso Projects**](doc/mcu_projects/readme.md)
	- For MCU cmake build, refer [**Getting Started on MCU cmake build**](doc/mcu_cmake/readme.md)
- MCUX projects for few examples added for LPC55s69, MCXN947, MCXA153. Refer [**mcux_project**](mcux_project)
- Pre-build binaries of vcom and NX CLI tool added. Refer [**Binaries**](binaries)
-  New examples -
	- Host co-processor example. Refer [**Host co-processor demo**](demos/nx/host_coprocessor/readme.md)
	- Qi Authentication example. Refer [**Qi Authentication demo**](demos/nx/sa_qi/readme.md)
	- ECC Standalone (session open from main). Refer [**ECC Standalone example**](demos/nx/ecc_standalone/readme.md)
	- VCOM example. Refer [**VCOM example**](demos/nx/vcom/readme.md)
- New Plugins
	- PKCS11 - Refer [**PKCS11 library**](plugin/pkcs11/readme.md)
	- PSA - Refer [**PSA files**](plugin/psa/README.md)
	- Mbed TLS ALT - Refer [**Mbed TLS ALT files**](plugin/mbedtls3x/readme.md)
- OpenSSL Provider changes
	- ECDSA functions handle different formats of SHA algorithm string (Example - "sha256" / "SHA256" / "SHA2-256")
- NX CLI tool changes
	- Added write access condition option in setkey command
	- New commands added - list-eckey, set-i2c_mgnt, set-cert_mgnt. For details refer - [**NX CLI Tool**](demos/nx/nx_cli_tool/readme.md).
- AWS Cloud example extended for MCXN947 platform.
- Fixes for static analysis findings and memory leak issues.
- APDU buffers (of APDU functions of nx_apdu.c) are made global.


## \[v02.04.00\]
- IMPORTANT: This is first version of GitHub release.
	- Note: Windows, frdmK64 and LPC platform support / example will be added in subsequent releases.
	- Previous versions of NX middleware are not released on GitHub
- Access Manager added (To support multiple client access SA)
- OpenSSL Provider changes
	- CSR generation extended for all SHA algorithms now. (Get context functions - 'sss_rsa_signature_get_ctx_params' and 'sss_ecdsa_signature_get_ctx_params' updated to handle all SHA algorithms).
	- Performance improvement : Provider is updated to store the client / server public key on host to avoid multiple secure authenticator reads during TLS connection.
	- OSSL algorithms are updated with algorithm properties.
	- Enable / Disable random number generation in nxp provider using compile time option - 'SSS_PROV_DISABLE_NX_RNG'. (Disabled by default)
	- ECC key management import functions added - to handle reference keys. If the input key is not reference key, the function returns error to roll back on other available providers.
	- ECC key management - match and duplicate functions added.
	- ECDSA digest verify support added (function - sss_ecdsa_signature_digest_verify).
- nx cli tool updated to set and get binary data form nx secure authenticator.
- Fixes for static analysis findings.

## \[v02.03.00\]
- lpc55s69 platform support added (cmake based build and mcuxpresso project).
- Mbedtls 3.x support added (Mbedtls version - 3.5.0). Using cmake option `-DNXMW_MBedTLS=`, NX middleware can be built with 2.x or 3.x version of Mbedtls.
- MCU SDK updated to version 2.14
- PSA APIs developed for NX secure authenticator. Refer - :ref:`psa-alt`.
- OpenSSL Provider - Provider updated to support reference keys in file format also.
- NX Cli tool - All provision scripts of demos (engine, provider, TLS examples) are updated to use nx cli tool.
- PKCS11 plugin improvements
- Code restructuring - Platform specific code is moved to board folder.
- Fixes for static analysis findings.

## \[v02.02.00\]
- Fixes for static analysis findings.
- `nx_cli_tool` added. Refer - :ref:`nx-cli-tool`.

## \[v02.01.00\]
- New Features
	- OpenSSL engine for NX Secure authenticator. Refer - :ref:`intro-openssl-engine`.
	- OpenSSL provider for NX Secure authenticator. Refer - :ref:`intro-openssl-provider`.
	- PKCS11 module for NX Secure authenticator. Refer - :ref:`intro-pkcs11-lib`.
	- TLS example updated for OpenSSL provider also. Refer - :ref:`tls-client-example`
	- FreeRTOS support for k64 platform. (NXMW_RTOS:STRING=FreeRTOS)
	- AWS cloud example for k64. Refer - :ref:`ksdk-demos-aws`
- Standalone MCUXpresso project for k64 added. Refer - :ref:`mcux_projects`.
- Default cmake option of sigma-i Curve type is changed to NIST_P (NXMW_Auth_Asymm_Host_Curve:STRING=NIST_P),
- Default certificate type of sigma-i authentication is changed to x509
- Fixes for static analysis findings.
- Folder restructuring
    - SSS and HostLib modules are moved to `lib` folder
    - Platform specific contents are moved to `boards` folder
    - All plugin modules are moved to folder - `plugin`

## \[v02.00.00\]
- Platforms supported - Windows, FRDM-k64 (native and vcom), Raspberry-pi

## \[v01.00.00\]
- Platforms supported - Windows, FRDM-k64 (only vcom)
- Supports Nx by VCOM.
- APIs & enum/types Changes
    - Added support for SSS and nx APIs.