# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

# This script retrieves the Device UID from the Secure Authenticator,
# identifies the corresponding application certificate from a x509_job_template_id_<val>_der_files
# file based on the UID, and loads the certificate into the Secure Authenticator.
#
# Before running this script, update the variable values as per the use case

# ######################################## SET VARIABLE VALUES ########################################

# Change the NX CLI Tool executable path here
export TOOL_PATH=../../../../binaries/tmp

# Set the smcom here
export SMCOM=t1oi2c

# Set port name here
export PORT=/dev/i2c-1

# Set secure tunneling type here
export SECURE_TUNNELING=ntag_aes128_ev2

# Set your preferred repository ID here
export REPO_ID=0x00

# Set folder path to the full path where DER files for the job template are stored.
export X509_APP_CERT_FULL_FOLDER_PATH=output/x509_job_template_id_24_der_files

# Check if the folder exists
if [ -d "$X509_APP_CERT_FULL_FOLDER_PATH" ]; then
    echo "Folder path exists"
else
    echo "Folder does not exist. Exiting..."
    exit 1
fi


# ######################################## EL2GO PARSER SCRIPT BEGINS HERE ########################################

$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth symmetric -sctunn $SECURE_TUNNELING -keyid 0x00

# reset repo, earse all certificate content and retains private key association, repo size and access condition
$TOOL_PATH/nxclitool certrepo-reset -repoid $REPO_ID -wcomm full -rcomm full -waccess 0x0 -raccess 0x0 -kcomm na
# load application certificate
$TOOL_PATH/nxclitool certrepo-load-cert -repoid $REPO_ID -certlevel leaf -kcomm na -in $X509_APP_CERT_FULL_FOLDER_PATH
# activate repo
$TOOL_PATH/nxclitool certrepo-activate -repoid $REPO_ID -kcomm na

$TOOL_PATH/nxclitool disconnect