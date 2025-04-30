:: Copyright 2025 NXP
:: SPDX-License-Identifier: BSD-3-Clause

:: This script can be used to personalize the secure element with X509 type certificates using the NX CLI Tool on Windows platform
:: After personalization, this script performs certrepo-read-cert and certrepo-read-metadata operations for the personalized repo.
:: Before running the script, ensure that the values of variables below are correct as per the use case.

:: ######################################## SET VARIABLE VALUES ########################################

:: Change the NX CLI Tool executable path here
set TOOL_PATH=..\..\..\..\binaries\tmp

:: Set the smcom here
set SMCOM=vcom

:: Set port name here
set PORT=COM3

:: Change the certificate file path as per your folder structure
set CERT_FOLDER_PATH=..\..\..\..\binaries\configuration\cert_depth3_x509_rev1\cert_and_key\nist_p

:: Set secure tunneling type here
set SECURE_TUNNELING=ntag_aes128_ev2

:: Set your preferred key ID here
set KEY_ID=0x00

:: Set your preferred repository ID here
set REPO_ID=0x00

:: Set your preferred curve type here
set CURVE=prime256v1

:: Set your preferred cert type here
:: set CERT_TYPE=host
set CERT_TYPE=device

:: Set your preferred i2c support here
set I2C_SUPPORT=0x01

:: Set i2c address here
set I2C_ADDRESS=0x20

:: Set protocolOptions here
set PROTOCOL_OPTIONS=0x1B85

:: Set output file path here
IF EXIST output (echo "output exists") else (mkdir output)
set OUT_FILE_PATH=output

:: Remove cached certificates if any
if exist %CERT_FOLDER_PATH%\..\..\cert_cache (rd /s /q "%CERT_FOLDER_PATH%\..\..\cert_cache")

:: ######################################## PERSONALIZATION SCRIPT BEGINS HERE ########################################

%TOOL_PATH%\nxclitool connect -smcom %SMCOM% -port %PORT% -auth symmetric -sctunn %SECURE_TUNNELING% -keyid 0x00

%TOOL_PATH%\nxclitool set-i2c_mgnt -i2csupport %I2C_SUPPORT% -i2caddr %I2C_ADDRESS% -protocoloptions %PROTOCOL_OPTIONS%

%TOOL_PATH%\nxclitool certrepo-load-key -keytype rootca -keyid %KEY_ID% -curve %CURVE% -certtype x509 -in %CERT_FOLDER_PATH%\%CERT_TYPE%_root_certificate.der
%TOOL_PATH%\nxclitool certrepo-load-key -keytype leaf -keyid %KEY_ID% -curve %CURVE% -certtype x509 -in %CERT_FOLDER_PATH%\%CERT_TYPE%_leaf_keypair.der
%TOOL_PATH%\nxclitool certrepo-create -repoid %REPO_ID% -keyid %KEY_ID% -wcomm full -rcomm full -waccess 0x0 -raccess 0x0 -kcomm na
%TOOL_PATH%\nxclitool certrepo-load-cert -repoid %REPO_ID% -certlevel leaf -kcomm na -in %CERT_FOLDER_PATH%\%CERT_TYPE%_leaf_certificate.der
%TOOL_PATH%\nxclitool certrepo-load-cert -repoid %REPO_ID% -certlevel p1 -kcomm na -in %CERT_FOLDER_PATH%\%CERT_TYPE%_p1_certificate.der
%TOOL_PATH%\nxclitool certrepo-load-cert -repoid %REPO_ID% -certlevel p2 -kcomm na -in %CERT_FOLDER_PATH%\%CERT_TYPE%_p2_certificate.der
%TOOL_PATH%\nxclitool certrepo-activate -repoid %REPO_ID% -kcomm na

:: Read certificates and metadata from the repository (optional for personalization)

%TOOL_PATH%\nxclitool certrepo-read-cert -repoid %REPO_ID% -certlevel leaf -kcomm na -out %OUT_FILE_PATH%\cert_leaf.pem
%TOOL_PATH%\nxclitool certrepo-read-cert -repoid %REPO_ID% -certlevel p1 -kcomm na -out %OUT_FILE_PATH%\cert_p1.pem
%TOOL_PATH%\nxclitool certrepo-read-cert -repoid %REPO_ID% -certlevel p2 -kcomm na -out %OUT_FILE_PATH%\cert_p2.pem

%TOOL_PATH%\nxclitool certrepo-read-metadata -repoid %REPO_ID%

%TOOL_PATH%\nxclitool disconnect