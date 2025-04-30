:: Copyright 2024 NXP
:: SPDX-License-Identifier: BSD-3-Clause

:: This script resets the repository in SA using the NX CLI Tool on Windows platform.
:: NOTE: This script does not deletes the repository.
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

:: Set your preferred repository ID here
set REPO_ID=0x01

:: ######################################## RESET REPO SCRIPT BEGINS HERE ########################################

%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth symmetric -sctunn %SECURE_TUNNELING% -keyid 0x00
%TOOL_PATH%\nxclitool certrepo-reset -repoid %REPO_ID% -wcomm full -rcomm full -waccess 0x0 -raccess 0x0 -kcomm na
%TOOL_PATH%\nxclitool disconnect