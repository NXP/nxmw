:: Copyright 2024 NXP
:: SPDX-License-Identifier: BSD-3-Clause

:: This script can be used to personalize the secure element with X509 type certificates using the NX CLI Tool on Windows platform

:: Set the path of vcom_nxclitool
set NXCLI_TOOL=".\..\..\PCWindows"

:: Change the certificate file path as per your folder structure
set CERT_FOLDER_PATH=.\cert_and_key\nist_p

set COMPORT=COM6


:: Set secure tunneling type here
set SECURE_TUNNELING=ntag_aes128_ev2

:: Set your preferred key ID here
set KEY_ID=0x00

:: Set your preferred repository ID here
set REPO_ID=0x00

:: Set your preferred curve type here
set CURVE=prime256v1

:: Personalization starts here

%NXCLI_TOOL%\vcom_nxclitool connect -smcom vcom -port %COMPORT% -auth symmetric -sctunn %SECURE_TUNNELING% -keyid 0x00

%NXCLI_TOOL%\vcom_nxclitool certrepo-load-key -keytype rootca -keyid %KEY_ID% -curve %CURVE% -certtype x509 -in %CERT_FOLDER_PATH%\host_root_certificate.der

%NXCLI_TOOL%\vcom_nxclitool disconnect

pause