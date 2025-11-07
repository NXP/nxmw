# EL2GO Provision

 EL2GO Provision is the process of securely loading application-specific X.509 certificates into a Secure Authenticator (SA) device. This step occurs after the certificates have been parsed and converted into the correct format (DER) using the EL2GO Parser. Provisioning ensures that the device is crypto-graphically bound to its identity and can participate in secure authentication protocols such as Sigma-I.

## Prerequisites

- Ensure openSSL has installed.

- Build nxclitool with vcom support with windows os [**Windows build**](../../doc/windows/readme.md).

- **Refer application note**  AN14838 EdgeLock 2GO x509 Certificate Service.

## Steps For EL2GO Provision

- Prepare the JSON file
    - if deviceId is in decimal, convert it to hex using convert_deviceid_json.py.
    - If it’s already a hex string, skip this step. [**convert_deviceid_json.py**](../../demos/nx/nx_cli_tool/scripts/convert_deviceid_json.py)
        - `python convert_deviceid_json.py input\x509_cert_job.json`

- Parse and extract certificates
    - The EL2GO Parser uses nxclitool to process an X.509 certificate job JSON file and extract the Application Certificate in DER format.
    - DER files are saved with the device ID as the filename in a subfolder named x509_job_template_id_val_der_files inside the specified output folder.
        - Update the variable X509_CERT_JOB_JSON_FILE_PATH in the batch file with the JSON file input path.
        - Update the variable X509_APP_CERT_FOLDER_PATH to the directory where the job template’s DER files are stored so the batch script can find them during provisioning.
        - [**nxclitool_el2go_parser.bat**](../../demos/nx/nx_cli_tool/scripts/nxclitool_el2go_parser.bat)

- Provision certificates to the device
    - Ensure DER certificate files are available in the specified directory.
    - Update the variable X509_APP_CERT_FULL_FOLDER_PATH in the batch file:[**nxclitool_el2go_provision.bat**](../../demos/nx/nx_cli_tool/scripts/nxclitool_el2go_provision.bat)

- Apply ECC key usage policies
    - To apply ECC key usage policies, use the following batch file:[**nxclitool_update_eccpolicy.bat**](../../demos/nx/nx_cli_tool/scripts/nxclitool_update_eccpolicy.bat)