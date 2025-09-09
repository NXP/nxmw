:: Copyright 2025 NXP
:: SPDX-License-Identifier: BSD-3-Clause

:: This script performs ecdsa using the NX CLI Tool on Windows platform
:: Before running this script, ensure a key is present in PEM format at the path specified in PRIV_KEY_PATH to be imported in the SA.
:: Before running this script, ensure a key is present in PEM format at the path specified in PUB_KEY_PATH to be ECDSA verify in the SA.
:: Before running this script, ensure a input data is present in txt format at the path specified in INPUT_FILE.
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
set KEY_CURVE_TYPE=prime256v1
::set KEY_CURVE_TYPE=brainpoolP256r1

:: Set repo ID here
set REPO_ID=0x01

:: Set input key path here
IF "%KEY_CURVE_TYPE%" == "prime256v1" (
	set PRIV_KEY_PATH=input\nist_p256_keypair.pem
	set PUB_KEY_PATH=input\nist_p256_pubkey.pem
) ELSE ( 
	set PRIV_KEY_PATH=input\bp256_keypair.pem
	set PUB_KEY_PATH=input\bp256_pubkey.pem
)

:: Set input/output file path here
set INPUT_FILE=input\input_file.txt
set DIGEST_FILE=output\digest_out.txt
set SIGNATURE_FILE=output\signature_out.txt

IF EXIST output (echo "output path exists") else (mkdir output)

:: ######################################## ECDSA SCRIPT BEGINS HERE ########################################

set SYMM_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn %SECURE_TUNNELING% -keyid 0x00)
set NONE_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn none -keyid 0x00)
set SIGMA_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn %SECURE_TUNNELING% -curve %AUTH_CURVE% -repoid %REPO_ID%)

IF %AUTH%==symmetric %SYMM_ST% ELSE IF %AUTH%==none %NONE_ST% ELSE %SIGMA_ST%

%TOOL_PATH%\nxclitool setkey -keyid %KEY_ID% -curve %KEY_CURVE_TYPE% -in %PRIV_KEY_PATH% -enable sign -waccess 0xE

%TOOL_PATH%\nxclitool dgst-sha256 -in %INPUT_FILE% -out %DIGEST_FILE% 

%TOOL_PATH%\nxclitool dgst-sign -keyid %KEY_ID% -in %DIGEST_FILE% -out %SIGNATURE_FILE% 

%TOOL_PATH%\nxclitool dgst-verify -curve %KEY_CURVE_TYPE% -pubkey %PUB_KEY_PATH% -signature %SIGNATURE_FILE% -in %DIGEST_FILE%

%TOOL_PATH%\nxclitool disconnect