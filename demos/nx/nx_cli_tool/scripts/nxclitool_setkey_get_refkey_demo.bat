:: Copyright 2024 NXP
:: SPDX-License-Identifier: BSD-3-Clause

:: This script sets a private key using the NX CLI Tool on Windows platform
:: Before running this script, ensure a key is present in PEM format at the path specified in PRIV_KEY_PATH to be imported in the SA.
:: Before running the script, ensure that the values of variables below are correct as per the use case.

:: ######################################## SET VARIABLE VALUES ########################################

:: Change the NX CLI Tool executable path here
set TOOL_PATH=..\..\..\..\binaries\tmp

:: Set the smcom here
set SMCOM=pcsc

:: Set port name here
set PORT=default

:: Set secure tunneling type here
set SECURE_TUNNELING=ntag_aes128_ev2

:: Set your preferred key ID here
set KEY_ID=0x02

:: Uncomment the curve type here and comment the rest
set CURVE=prime256v1
:: set CURVE=brainpoolP256r1

:: Uncomment the required auth type and comment the rest
:: set AUTH=none
set AUTH=symmetric
:: set AUTH=sigma_i_verifier
:: set AUTH=sigma_i_prover

:: Uncomment the curve type for authentication and comment the rest (not used in case of symmetric auth or auth none)
set AUTH_CURVE=prime256v1
:: set AUTH_CURVE=brainpoolP256r1

:: Set repo ID here
set REPO_ID=0x01

:: Set input key path here
set PRIV_KEY_PATH=input\nist_p256_keypair.pem
set PUB_KEY_PATH=input\nist_p256_pubkey.pem

IF EXIST output (echo "output path exists") else (mkdir output)

:: ######################################## SET KEY SCRIPT BEGINS HERE ########################################

set SYMM_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn %SECURE_TUNNELING% -keyid 0x00)
set NONE_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn none -keyid 0x00)
set SIGMA_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn %SECURE_TUNNELING% -curve %AUTH_CURVE% -repoid %REPO_ID%)

IF %AUTH%==symmetric %SYMM_ST% ELSE IF %AUTH%==none %NONE_ST% ELSE %SIGMA_ST%

%TOOL_PATH%\nxclitool setkey -keyid %KEY_ID% -curve %CURVE% -in %PRIV_KEY_PATH% -enable sign -waccess 0xE

%TOOL_PATH%\nxclitool list-eckey

%TOOL_PATH%\nxclitool disconnect

%TOOL_PATH%\nxclitool get-ref-key -keyid %KEY_ID% -in %PUB_KEY_PATH% -out output\ref.key