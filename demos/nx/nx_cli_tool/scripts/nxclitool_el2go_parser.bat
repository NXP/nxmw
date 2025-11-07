:: Copyright 2025 NXP
:: SPDX-License-Identifier: BSD-3-Clause

:: This script parses application certificates from a JSON file based on the UID.
:: OpenSSL is used to convert the certificate from PEM to DER format.
:: It creates a folder named x509_job_template_id_<templateId>_der_files and saves the X.509 certificate in DER format.

:: Before running this script, update the variable values as per the use case

:: ######################################## SET VARIABLE VALUES ########################################

:: Change the NX CLI Tool executable path here
set TOOL_PATH=..\..\..\..\binaries\tmp

:: Set Json input file path
set X509_CERT_JOB_JSON_FILE_PATH=input\x509_cert_job.json

:: Set folder path to the base output directory for application certificates
set X509_APP_CERT_FOLDER_PATH=output

:: Check if the folder exists
IF EXIST "%X509_APP_CERT_FOLDER_PATH%" (
    echo Folder path exists
) ELSE (
    echo Folder does not exist. Exiting...
    exit /b 1
)

:: ######################################## EL2GO PARSER SCRIPT BEGINS HERE ########################################

:: el2go parser, parse application certificate and save it in DER format, at the specified folder location
%TOOL_PATH%\nxclitool el2go-parser -in %X509_CERT_JOB_JSON_FILE_PATH% -out %X509_APP_CERT_FOLDER_PATH%
