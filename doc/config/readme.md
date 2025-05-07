# CMake Options


## NXMW_NX_Type: The NX Secure Authenticator Type

You can compile host library for different OS Applications of NX Secure Authenticator listed below.

``-DNXMW_NX_Type=None``: Compiling without any NX Type Support

``-DNXMW_NX_Type=NX_R_DA``: Application (DF name 0xD2760000850101)

``-DNXMW_NX_Type=NX_PICC``: MF (DF name 0xD2760000850100)


## NXMW_Host: Host where the software stack is running

For e.g. Windows, PC Linux, Embedded Linux, Kinetis like embedded platform

``-DNXMW_Host=PCWindows``: PC/Laptop Windows

``-DNXMW_Host=PCLinux64``: PC/Laptop Linux64

``-DNXMW_Host=lpcxpresso55s``: Embedded LPCXpresso55s

``-DNXMW_Host=Raspbian``: Embedded Linux on RaspBerry PI

``-DNXMW_Host=frdmmcxn947``: Embedded Freedom MCXN947

``-DNXMW_Host=frdmmcxn947``: Embedded Freedom MCXA153


## NXMW_SMCOM: Communication Interface

How the host library communicates to the Secure Authenticator.
This may be directly over an I2C interface on embedded platform.
Or sometimes over Remote protocol like JRCP_V1_AM / VCOM from PC.

``-DNXMW_SMCOM=None``: Not using any Communication layer

``-DNXMW_SMCOM=VCOM``: Virtual COM Port

``-DNXMW_SMCOM=T1oI2C_GP1_0``: GP Spec

``-DNXMW_SMCOM=PCSC``: CCID PC/SC reader interface

``-DNXMW_SMCOM=JRCP_V1_AM``: Socket Interface Implementation.
   This is the interface used by the clients to connect from
   Host PC to access manager (which is run as a server in the Linux PC)


## NXMW_HostCrypto: Counterpart Crypto on Host

What is being used as a cryptographic library on the host.
As of now only OpenSSL / mbedTLS is supported

``-DNXMW_HostCrypto=MBEDTLS``: Use mbedTLS as host crypto

``-DNXMW_HostCrypto=OPENSSL``: Use OpenSSL as host crypto

``-DNXMW_HostCrypto=None``: No Host Crypto
    Note,  the security of configuring NX to be used without HostCrypto
    needs to be assessed from system security point of view


## NXMW_RTOS: Choice of Operating system

Default would mean nothing special.
i.e. Without any RTOS on embedded system, or default APIs on PC/Linux

``-DNXMW_RTOS=Default``: No specific RTOS. Either bare metal on embedded system or native Linux or Windows OS

``-DNXMW_RTOS=FreeRTOS``: Free RTOS for embedded systems


## NXMW_Auth: NX Authentication

This settings is used by examples to connect using various options to authenticate with the NX SE.

``-DNXMW_Auth=None``: Use the default session (i.e. session less) login

``-DNXMW_Auth=SIGMA_I_Verifier``: SIGMA I Verifier

``-DNXMW_Auth=SIGMA_I_Prover``: SIGMA I Prover

``-DNXMW_Auth=SYMM_Auth``: Symmetric Authentication


## NXMW_Log: Logging

Set the logging level using this setting

``-DNXMW_Log=Default``: Default Logging

``-DNXMW_Log=Verbose``: Very Verbose logging

``-DNXMW_Log=Silent``: Totally silent logging


## CMAKE_BUILD_TYPE

Refer: https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html

For embedded builds, this choices sets optimization levels.
For MSVC builds, build type is selected from IDE As well

``-DCMAKE_BUILD_TYPE=Debug``: For developer

``-DCMAKE_BUILD_TYPE=Release``: Optimization enabled and debug symbols removed

``-DCMAKE_BUILD_TYPE=RelWithDebInfo``: Optimization enabled but with debug symbols

``-DCMAKE_BUILD_TYPE=``: Empty Allowed


## NXMW_Secure_Tunneling: Secure Tunneling (Secure Messaging)

Successful Symmetric authentication and SIGMA-I mutual authentication results in the establishment of
session keys and session IVs.
These are used to encrypt and integrity protect the payloads to be exchanged.

``-DNXMW_Secure_Tunneling=None``: Plain Text

``-DNXMW_Secure_Tunneling=NTAG_AES128_AES256_EV2``: NTAG AES - 128 or AES - 256 (EV2) Secure Channel. Only valid for Sigma-I. Host supports both AES - 128 and AES - 256. The secure channel security strength is selected based on the SE configuration.

``-DNXMW_Secure_Tunneling=NTAG_AES128_EV2``: Only NTAG AES - 128 (EV2) Secure Channel

``-DNXMW_Secure_Tunneling=NTAG_AES256_EV2``: Only NTAG AES - 256 (EV2) Secure Channel


## NXMW_Auth_Asymm_Host_PK_Cache: Host public key cache**

Support a cache of validated public keys and parent certificates on host.
This is utilized to accelerate protocol execution time by removing the need
to validate public key and certificates that have been previously verified.

Secure authenticator cache is enabled by Cmd.SetConfiguration. Refer [**Enable Certificate Cache Example**](../../demos/nx/cert_cache/readme.md) for more information.

``-DNXMW_Auth_Asymm_Host_PK_Cache=Disabled``: Host's Public Key And Parent Certificates Cache Disabled

``-DNXMW_Auth_Asymm_Host_PK_Cache=Enabled``: Host's Public Key And Parent Certificates Cache Enabled


## NXMW_Auth_Asymm_Cert_Repo_Id: Certificate Repository Id

Certificate Repository Id is used to identify certificate repository. Used in both personalization and demos with Sigma-I authentication.
In personalization, it indicates repository to be initialized. In demos, it indicates repository to be used for Sigma-I authentication

``-DNXMW_Auth_Asymm_Cert_Repo_Id=0``: Certificate Repository 0

``-DNXMW_Auth_Asymm_Cert_Repo_Id=1``: Certificate Repository 1

``-DNXMW_Auth_Asymm_Cert_Repo_Id=2``: Certificate Repository 2

``-DNXMW_Auth_Asymm_Cert_Repo_Id=3``: Certificate Repository 3

``-DNXMW_Auth_Asymm_Cert_Repo_Id=4``: Certificate Repository 4

``-DNXMW_Auth_Asymm_Cert_Repo_Id=5``: Certificate Repository 5

``-DNXMW_Auth_Asymm_Cert_Repo_Id=6``: Certificate Repository 6

``-DNXMW_Auth_Asymm_Cert_Repo_Id=7``: Certificate Repository 7


## NXMW_Auth_Asymm_Cert_SK_Id: Certificate Private Key Id

Id of ECC private key associated with this
repository. Used in personalization for Sigma-I.

``-DNXMW_Auth_Asymm_Cert_SK_Id=0``: Certificate Private KeyId 0

``-DNXMW_Auth_Asymm_Cert_SK_Id=1``: Certificate Private KeyId 1

``-DNXMW_Auth_Asymm_Cert_SK_Id=2``: Certificate Private KeyId 2

``-DNXMW_Auth_Asymm_Cert_SK_Id=3``: Certificate Private KeyId 3

``-DNXMW_Auth_Asymm_Cert_SK_Id=4``: Certificate Private KeyId 4


## NXMW_Auth_Asymm_CA_Root_Key_Id: Key ID of CA Root Public Key

Id of CA root public key associated with this repository. Used in personalization for Sigma-I.

``-DNXMW_Auth_Asymm_CA_Root_Key_Id=0``: CA Root KeyId 0

``-DNXMW_Auth_Asymm_CA_Root_Key_Id=1``: CA Root KeyId 1

``-DNXMW_Auth_Asymm_CA_Root_Key_Id=2``: CA Root KeyId 2

``-DNXMW_Auth_Asymm_CA_Root_Key_Id=3``: CA Root KeyId 3

``-DNXMW_Auth_Asymm_CA_Root_Key_Id=4``: CA Root KeyId 4


## NXMW_Auth_Symm_App_Key_Id: Application Key ID

Indicate application key which is used in symmetric authentication.

``-DNXMW_Auth_Symm_App_Key_Id=0``: Application KeyId 0

``-DNXMW_Auth_Symm_App_Key_Id=1``: Application KeyId 1

``-DNXMW_Auth_Symm_App_Key_Id=2``: Application KeyId 2

``-DNXMW_Auth_Symm_App_Key_Id=3``: Application KeyId 3

``-DNXMW_Auth_Symm_App_Key_Id=4``: Application KeyId 4


## NXMW_Auth_Asymm_Host_Curve: Host EC domain curve type

EC domain curve used for session key generation and
session signature. Used in demos with Sigma-I authentication.

``-DNXMW_Auth_Asymm_Host_Curve=NIST_P``: EC Curve NIST-P

``-DNXMW_Auth_Asymm_Host_Curve=BRAINPOOL``: EC Curve Brainpool


## NXMW_OpenSSL: For PC, OpenSSL version to pick up

On Linux based builds, this option has no impact, because the build system
picks up the default available/installed OpenSSL from the system directly.
Also, this option has no impact if NXMW_HostCrypto is not selected as OPENSSL.

``-DNXMW_OpenSSL=1_1_1``: Use latest 1.1.1 version (Only applicable on PC)

``-DNXMW_OpenSSL=3_0``: Use 3.0 version (Only applicable on PC)


## NXMW_MBedTLS: Which MBedTLS version to choose

This option has no impact if NXMW_HostCrypto is not selected as MBEDTLS.

``-DNXMW_MBedTLS=2_X``: Use 2.X version

``-DNXMW_MBedTLS=3_X``: Use 3.X version


## NXMW_Auth_Symm_Diversify: Diversification of symmetric authentication key

When enabled, key used for symmetric authentication is diversification key derived from master key.

Otherwise master key is used.

``-DNXMW_Auth_Symm_Diversify=Disabled``: Symm Auth Key Diversification Disabled

``-DNXMW_Auth_Symm_Diversify=Enabled``: Symm Auth Key Diversification Enabled


## NXMW_All_Auth_Code: Enable all authentication code
When enabled, all the authentication code is enabled in nx library.

``-DNXMW_All_Auth_Code=Disabled``: Enable only required authentication code (Based on NXMW_Auth Cmake option)

``-DNXMW_All_Auth_Code=Enabled``: Enable all authentication code


## NXMW_mbedTLS_ALT: ALT Engine implementation for mbedTLS

When set to None, mbedTLS would not use ALT Implementation to connect to / use Secure Authenticator.
This needs to be set to PSA for PSA example over SSS APIs

``-DNXMW_mbedTLS_ALT=SSS``: Enable SSS as ALT

``-DNXMW_mbedTLS_ALT=PSA``: Enable TF-M based on PSA as ALT

``-DNXMW_mbedTLS_ALT=None``: Not using any mbedTLS_ALT

>**NOTE**: When this is set as PSA, cloud demos can not work with mbedTLS


## NXMW_SA_Type: Enable host certificates of A30 for Sigma-I Authentication

When Secure Authenticator type is selected, respective host certificates are enabled in NX library.

``-DNXMW_SA_Type=A30``: Enable A30 host cert for Sigma-I authentication

``-DNXMW_SA_Type=NTAG_X_DNA``: Enable NTAG_X_DNA host cert for Sigma-I authentication

``-DNXMW_SA_Type=NXP_INT_CONFIG``: Enable NXP_INT_CONFIG host cert for Sigma-I authentication

``-DNXMW_SA_Type=Other``: Enable Other host cert for Sigma-I authentication
