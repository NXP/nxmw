:: Copyright 2025 NXP
:: SPDX-License-Identifier: BSD-3-Clause

:: This script performs ecdh using the NX CLI Tool on Windows platform
:: Before running this script, ensure a key is present in PEM format at the path specified in PEER_PUB_KEY to derive ECDH in the SA.
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
set KEY_CURVE_TYPE=prime256v1
::set KEY_CURVE_TYPE=brainpoolP256r1

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

:: Set input/output file path here

IF "%KEY_CURVE_TYPE%" == "prime256v1" (
	set PEER_PUB_KEY=input/nist_p256_peer_pubkey.pem
) ELSE ( 
	set PEER_PUB_KEY=input/bp256_peer_pubkey.pem
)
set SHARED_SECRET_KEY=output\sh_key_out.txt

IF EXIST output (echo "output path exists") else (mkdir output)

:: ######################################## ECDH SCRIPT BEGINS HERE ########################################

set SYMM_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn %SECURE_TUNNELING% -keyid 0x00)
set NONE_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn none -keyid 0x00)
set SIGMA_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn %SECURE_TUNNELING% -curve %AUTH_CURVE% -repoid %REPO_ID%)

IF %AUTH%==symmetric %SYMM_ST% ELSE IF %AUTH%==none %NONE_ST% ELSE %SIGMA_ST%

%TOOL_PATH%\nxclitool genkey -keyid %KEY_ID% -curve %KEY_CURVE_TYPE% -enable ecdh -waccess 0xE

%TOOL_PATH%\nxclitool derive-ecdh -keyid %KEY_ID% -curve %KEY_CURVE_TYPE% -peerkey %PEER_PUB_KEY% -out %SHARED_SECRET_KEY%

%TOOL_PATH%\nxclitool disconnect