:: Copyright 2025 NXP
:: SPDX-License-Identifier: BSD-3-Clause

:: This script set config i2c management SA
:: Before running the script, ensure that the values of variables below are correct as per the use case.

:: ######################################## SET VARIABLE VALUES ########################################

:: Change the NX CLI Tool executable path here
set TOOL_PATH=..\..\..\..\binaries\tmp

:: Set the smcom here
set SMCOM=pcsc

:: Set port name here
set PORT=default

:: Set the key ID here for key generation
set KEY_ID=0x00

:: Set secure tunneling type here
set SECURE_TUNNELING=ntag_aes128_ev2

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
set REPO_ID=0x00

:: Set leaf cache size here
set LEAF_CACHE_SIZE=0x08

:: Set Intermediate certificate cache size here
set INTERM_CACHE_SIZE=0x08

:: Set Enable SIGMA-I cache here
set ENABLE_SIGMA_I_CACHE=0x01
::set DISABLE_SIGMA_I_CACHE=0x00

:: Set feature selection here
set FEATURE_SELECTION=%ENABLE_SIGMA_I_CACHE%

:: ######################################## GET UID SCRIPT BEGINS HERE ########################################

set SYMM_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn %SECURE_TUNNELING% -keyid 0x00)
set NONE_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn none -keyid 0x00)
set SIGMA_ST=(%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth %AUTH% -sctunn %SECURE_TUNNELING% -curve %AUTH_CURVE% -repoid %REPO_ID%)

IF %AUTH%==symmetric %SYMM_ST% ELSE IF %AUTH%==none %NONE_ST% ELSE %SIGMA_ST%

%TOOL_PATH%\nxclitool set-cert_mgnt -leafcachesize %LEAF_CACHE_SIZE% -intermcachesize %INTERM_CACHE_SIZE% -featureselection %FEATURE_SELECTION% -wcomm plain -waccess 0x00

%TOOL_PATH%\nxclitool disconnect