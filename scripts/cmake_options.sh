# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#
# #############################################################
# This file is generated using a script
# #############################################################
#


### NXMW_NX_Type : The NX Secure Authenticator Type
# You can compile host library for different OS Applications of NX Secure Authenticator listed below.

doNXMW_NX_Type_None_ON="-DNXMW_NX_Type=None" #Compiling without any NX Type Support

doNXMW_NX_Type_NX_R_DA_ON="-DNXMW_NX_Type=NX_R_DA" #Application (DF name 0xD2760000850101)

doNXMW_NX_Type_NX_PICC_ON="-DNXMW_NX_Type=NX_PICC" #MF (DF name 0xD2760000850100)


### NXMW_Host : Host where the software stack is running
# 
# e.g. Windows, PC Linux, Embedded Linux, Kinetis like embedded platform

doNXMW_Host_PCWindows_ON="-DNXMW_Host=PCWindows" #PC/Laptop Windows

doNXMW_Host_PCLinux64_ON="-DNXMW_Host=PCLinux64" #PC/Laptop Linux64

doNXMW_Host_frdmk64f_ON="-DNXMW_Host=frdmk64f" #Embedded Kinetis Freedom K64F

doNXMW_Host_lpcxpresso55s_ON="-DNXMW_Host=lpcxpresso55s" #Embedded LPCXpresso55s

doNXMW_Host_Raspbian_ON="-DNXMW_Host=Raspbian" #Embedded Linux on RaspBerry PI


### NXMW_SMCOM : Communication Interface
# 
# How the host library communicates to the Secure Authenticator.
# This may be directly over an I2C interface on embedded platform.
# Or sometimes over Remote protocol like JRCP_V1_AM / VCOM from PC.

doNXMW_SMCOM_None_ON="-DNXMW_SMCOM=None" #Not using any Communication layer

doNXMW_SMCOM_VCOM_ON="-DNXMW_SMCOM=VCOM" #Virtual COM Port

doNXMW_SMCOM_T1oI2C_GP1_0_ON="-DNXMW_SMCOM=T1oI2C_GP1_0" #GP Spec

doNXMW_SMCOM_PCSC_ON="-DNXMW_SMCOM=PCSC" #CCID PC/SC reader interface

#Socket Interface Old Implementation.
# This is the interface used from Host PC when when we run jrcpv1_server
# from the linux PC.

doNXMW_SMCOM_JRCP_V1_AM_ON="-DNXMW_SMCOM=JRCP_V1_AM"


### NXMW_HostCrypto : Counterpart Crypto on Host
# 
# What is being used as a cryptographic library on the host.
# As of now only OpenSSL / mbedTLS is supported

doNXMW_HostCrypto_MBEDTLS_ON="-DNXMW_HostCrypto=MBEDTLS" #Use mbedTLS as host crypto

doNXMW_HostCrypto_OPENSSL_ON="-DNXMW_HostCrypto=OPENSSL" #Use OpenSSL as host crypto

#NO Host Crypto
# Note,  the security of configuring Nx to be used without HostCrypto
# needs to be assessed from system security point of view

doNXMW_HostCrypto_None_ON="-DNXMW_HostCrypto=None"


### NXMW_RTOS : Choice of Operating system
# 
# Default would mean nothing special.
# i.e. Without any RTOS on embedded system, or default APIs on PC/Linux

doNXMW_RTOS_Default_ON="-DNXMW_RTOS=Default" #No specific RTOS. Either bare matal on embedded system or native linux or Windows OS

doNXMW_RTOS_FreeRTOS_ON="-DNXMW_RTOS=FreeRTOS" #Free RTOS for embedded systems


### NXMW_Auth : NX Authentication
# 
# This settings is used by examples to connect using various options
# to authenticate with the Nx SE.
# Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for the combinations of session auth and secure tunneling modes.

doNXMW_Auth_None_ON="-DNXMW_Auth=None" #Use the default session (i.e. session less) login

doNXMW_Auth_SIGMA_I_Verifier_ON="-DNXMW_Auth=SIGMA_I_Verifier" #SIGMA I Verifier

doNXMW_Auth_SIGMA_I_Prover_ON="-DNXMW_Auth=SIGMA_I_Prover" #SIGMA I Prover

doNXMW_Auth_SYMM_Auth_ON="-DNXMW_Auth=SYMM_Auth" #Symmetric Authentication


### NXMW_Log : Logging

doNXMW_Log_Default_ON="-DNXMW_Log=Default" #Default Logging

doNXMW_Log_Verbose_ON="-DNXMW_Log=Verbose" #Very Verbose logging

doNXMW_Log_Silent_ON="-DNXMW_Log=Silent" #Totally silent logging

doNXMW_Log_SeggerRTT_ON="-DNXMW_Log=SeggerRTT" #Segger Real Time Transfer (For Test Automation, NXP Internal)


### CMAKE_BUILD_TYPE : See https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html
# 
# For embedded builds, this choices sets optimization levels.
# For MSVC builds, build type is selected from IDE As well

doCMAKE_BUILD_TYPE_Debug_ON="-DCMAKE_BUILD_TYPE=Debug" #For developer

doCMAKE_BUILD_TYPE_Release_ON="-DCMAKE_BUILD_TYPE=Release" #Optimization enabled and debug symbols removed

doCMAKE_BUILD_TYPE_RelWithDebInfo_ON="-DCMAKE_BUILD_TYPE=RelWithDebInfo" #Optimization enabled but with debug symbols

doCMAKE_BUILD_TYPE__ON="-DCMAKE_BUILD_TYPE=" #Empty Allowed


### NXMW_Secure_Tunneling : Secure Tunneling(Secure Messaging)
# 
# Successful Symmetric authentication and SIGMA-I mutual authentication results in the establishment of
# session keys and session IVs.
# These are used to encrypt and integrity protect the payloads to be exchanged.
# Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for the combinations of session auth and secure tunneling modes.

doNXMW_Secure_Tunneling_None_ON="-DNXMW_Secure_Tunneling=None" #Plain Text

doNXMW_Secure_Tunneling_NTAG_AES128_AES256_EV2_ON="-DNXMW_Secure_Tunneling=NTAG_AES128_AES256_EV2" #NTAG AES-128 or AES-256 (EV2) Secure Channel. Only valid for Sigma-I. Host supports both AES-128 and AES-256. The secure channel security strength is selected based on the SE configuration.

doNXMW_Secure_Tunneling_NTAG_AES128_EV2_ON="-DNXMW_Secure_Tunneling=NTAG_AES128_EV2" #Only NTAG AES-128 (EV2) Secure Channel

doNXMW_Secure_Tunneling_NTAG_AES256_EV2_ON="-DNXMW_Secure_Tunneling=NTAG_AES256_EV2" #Only NTAG AES-256 (EV2) Secure Channel


### NXMW_Auth_Asymm_Host_PK_Cache : Host public key cache
# 
# Support a cache of validated public keys and parent certificates on host.
# This is utilized to accelerate protocol execution time by removing the need 
# to validate public key and certificates that have been previously verified. Refer to :numref:`nx-auth-sessions` --- :ref:`nx-auth-sessions` for more information.
# 
# Secure authenticator cache is enabled by Cmd.SetConfiguration. Ref to section 4.6.2 for more information.

doNXMW_Auth_Asymm_Host_PK_Cache_Disabled_ON="-DNXMW_Auth_Asymm_Host_PK_Cache=Disabled" #Host's Public Key And Parent Certificates Cache Disabled

doNXMW_Auth_Asymm_Host_PK_Cache_Enabled_ON="-DNXMW_Auth_Asymm_Host_PK_Cache=Enabled" #Host's Public Key And Parent Certificates Cache Enabled


### NXMW_Auth_Asymm_Cert_Repo_Id : Certificate Repository Id
# 
# Certificate Repository Id is used to identify certificate repository. Used in both personalization and demos with Sigma-I authentication. 
# In personalization, it indicates repository to be initialized. In demos, it indicates repository to be used for Sigma-I authentication

doNXMW_Auth_Asymm_Cert_Repo_Id_0_ON="-DNXMW_Auth_Asymm_Cert_Repo_Id=0" #Certificate Repository 0

doNXMW_Auth_Asymm_Cert_Repo_Id_1_ON="-DNXMW_Auth_Asymm_Cert_Repo_Id=1" #Certificate Repository 1

doNXMW_Auth_Asymm_Cert_Repo_Id_2_ON="-DNXMW_Auth_Asymm_Cert_Repo_Id=2" #Certificate Repository 2

doNXMW_Auth_Asymm_Cert_Repo_Id_3_ON="-DNXMW_Auth_Asymm_Cert_Repo_Id=3" #Certificate Repository 3

doNXMW_Auth_Asymm_Cert_Repo_Id_4_ON="-DNXMW_Auth_Asymm_Cert_Repo_Id=4" #Certificate Repository 4

doNXMW_Auth_Asymm_Cert_Repo_Id_5_ON="-DNXMW_Auth_Asymm_Cert_Repo_Id=5" #Certificate Repository 5

doNXMW_Auth_Asymm_Cert_Repo_Id_6_ON="-DNXMW_Auth_Asymm_Cert_Repo_Id=6" #Certificate Repository 6

doNXMW_Auth_Asymm_Cert_Repo_Id_7_ON="-DNXMW_Auth_Asymm_Cert_Repo_Id=7" #Certificate Repository 7


### NXMW_Auth_Asymm_Cert_SK_Id : Certificate Private Key Id
# 
# Id of ECC private key associated with this 
# repository. Used in personalization for Sigma-I.

doNXMW_Auth_Asymm_Cert_SK_Id_0_ON="-DNXMW_Auth_Asymm_Cert_SK_Id=0" #Certificate Private KeyId 0

doNXMW_Auth_Asymm_Cert_SK_Id_1_ON="-DNXMW_Auth_Asymm_Cert_SK_Id=1" #Certificate Private KeyId 1

doNXMW_Auth_Asymm_Cert_SK_Id_2_ON="-DNXMW_Auth_Asymm_Cert_SK_Id=2" #Certificate Private KeyId 2

doNXMW_Auth_Asymm_Cert_SK_Id_3_ON="-DNXMW_Auth_Asymm_Cert_SK_Id=3" #Certificate Private KeyId 3

doNXMW_Auth_Asymm_Cert_SK_Id_4_ON="-DNXMW_Auth_Asymm_Cert_SK_Id=4" #Certificate Private KeyId 4


### NXMW_Auth_Asymm_CA_Root_Key_Id : Key ID of CA Root Public Key
# 
# Id of CA root public key associated with this 
# repository. Used in personalization for Sigma-I.

doNXMW_Auth_Asymm_CA_Root_Key_Id_0_ON="-DNXMW_Auth_Asymm_CA_Root_Key_Id=0" #CA Root KeyId 0

doNXMW_Auth_Asymm_CA_Root_Key_Id_1_ON="-DNXMW_Auth_Asymm_CA_Root_Key_Id=1" #CA Root KeyId 1

doNXMW_Auth_Asymm_CA_Root_Key_Id_2_ON="-DNXMW_Auth_Asymm_CA_Root_Key_Id=2" #CA Root KeyId 2

doNXMW_Auth_Asymm_CA_Root_Key_Id_3_ON="-DNXMW_Auth_Asymm_CA_Root_Key_Id=3" #CA Root KeyId 3

doNXMW_Auth_Asymm_CA_Root_Key_Id_4_ON="-DNXMW_Auth_Asymm_CA_Root_Key_Id=4" #CA Root KeyId 4


### NXMW_Auth_Symm_App_Key_Id : application Key ID
# 
# Indicate application key which is used in symmetric authentication.

doNXMW_Auth_Symm_App_Key_Id_0_ON="-DNXMW_Auth_Symm_App_Key_Id=0" #Application KeyId 0

doNXMW_Auth_Symm_App_Key_Id_1_ON="-DNXMW_Auth_Symm_App_Key_Id=1" #Application KeyId 1

doNXMW_Auth_Symm_App_Key_Id_2_ON="-DNXMW_Auth_Symm_App_Key_Id=2" #Application KeyId 2

doNXMW_Auth_Symm_App_Key_Id_3_ON="-DNXMW_Auth_Symm_App_Key_Id=3" #Application KeyId 3

doNXMW_Auth_Symm_App_Key_Id_4_ON="-DNXMW_Auth_Symm_App_Key_Id=4" #Application KeyId 4


### NXMW_Auth_Asymm_Host_Curve : Host EC domain curve type
# 
# EC domain curve used for session key generation and 
# session signature. Used in demos with Sigma-I authentication.

doNXMW_Auth_Asymm_Host_Curve_NIST_P_ON="-DNXMW_Auth_Asymm_Host_Curve=NIST_P" #EC Curve NIST-P

doNXMW_Auth_Asymm_Host_Curve_BRAINPOOL_ON="-DNXMW_Auth_Asymm_Host_Curve=BRAINPOOL" #EC Curve Brainpool


### NXMW_OpenSSL : For PC, which OpenSSL to pick up
# 
# On Linux based builds, this option has no impact, because the build system
# picks up the default available/installed OpenSSL from the system directly.

doNXMW_OpenSSL_1_1_1_ON="-DNXMW_OpenSSL=1_1_1" #Use latest 1.1.1 version (Only applicable on PC)

doNXMW_OpenSSL_3_0_ON="-DNXMW_OpenSSL=3_0" #Use 3.0 version (Only applicable on PC)


### NXMW_MBedTLS : Which MBedTLS version to choose

doNXMW_MBedTLS_2_X_ON="-DNXMW_MBedTLS=2_X" #Use 2.X version

doNXMW_MBedTLS_3_X_ON="-DNXMW_MBedTLS=3_X" #Use 3.X version


### NXMW_Auth_Symm_Diversify : Diversification of symmetric authentication key
# 
# When enabled, key used for symmetric authentication is diversification key derived from master key.
# 
# Otherwise master key is used.

doNXMW_Auth_Symm_Diversify_Disabled_ON="-DNXMW_Auth_Symm_Diversify=Disabled" #Symm Auth Key Diversification Disabled

doNXMW_Auth_Symm_Diversify_Enabled_ON="-DNXMW_Auth_Symm_Diversify=Enabled" #Symm Auth Key Diversification Enabled


### NXMW_All_Auth_Code : Enable all authentication code
# When enabled, all the authentication code is enabled in nx library.

doNXMW_All_Auth_Code_Disabled_ON="-DNXMW_All_Auth_Code=Disabled" #Enable only required authentication code (Based on NXMW_Auth Cmake option)

doNXMW_All_Auth_Code_Enabled_ON="-DNXMW_All_Auth_Code=Enabled" #Enable all authentication code


### NXMW_mbedTLS_ALT : ALT Engine implementation for mbedTLS
# 
# When set to None, mbedTLS would not use ALT Implementation to connect to / use Secure Authenticator.
# This needs to be set to PSA for PSA example over SSS APIs

doNXMW_mbedTLS_ALT_SSS_ON="-DNXMW_mbedTLS_ALT=SSS" #Use SSS Layer ALT implementation

doNXMW_mbedTLS_ALT_PSA_ON="-DNXMW_mbedTLS_ALT=PSA" #Enable TF-M based on PSA as ALT

#Not using any mbedTLS_ALT
# 
# When this is selected, cloud demos can not work with mbedTLS

doNXMW_mbedTLS_ALT_None_ON="-DNXMW_mbedTLS_ALT=None"


### NXMW_SA_Type : Enable host certificates of A30 for sigma-I Authentication
# When Secure Authenticator type is selected, respective host certificates are enabled in nx library.

doNXMW_SA_Type_A30_ON="-DNXMW_SA_Type=A30" #Enable A30 host cert for sigma-I authentication

doNXMW_SA_Type_NTAG_X_DNA_ON="-DNXMW_SA_Type=NTAG_X_DNA" #Enable NTAG_X_DNA host cert for sigma-I authentication

doNXMW_SA_Type_NXP_INT_CONFIG_ON="-DNXMW_SA_Type=NXP_INT_CONFIG" #Enable NXP_INT_CONFIG host cert for sigma-I authentication

doNXMW_SA_Type_Other_ON="-DNXMW_SA_Type=Other" #Enable Other host cert for sigma-I authentication

# Create and use shared libraries
doWithSharedLIB_ON="-DWithSharedLIB=ON"
doWithSharedLIB_OFF="-DWithSharedLIB=OFF"

# NXP Internal
doNXPInternal_ON="-DNXPInternal=ON"
doNXPInternal_OFF="-DNXPInternal=OFF"

# Compile with Code Coverage
doWithCodeCoverage_ON="-DWithCodeCoverage=ON"
doWithCodeCoverage_OFF="-DWithCodeCoverage=OFF"
