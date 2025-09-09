# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

# This script performs ecdsa using the NX CLI Tool on Linux platform
# Before running this script, ensure a key is present in PEM format at the path specified in PRIV_KEY_PATH to be imported in the SA.
# Before running this script, ensure a key is present in PEM format at the path specified in PUB_KEY_PATH to be ECDSA verify in the SA.
# Before running this script, ensure a input data is present in txt format at the path specified in INPUT_FILE.
# Before running the script, ensure that the values of variables below are correct as per the use case.

# ######################################## SET VARIABLE VALUES ########################################

# Change the NX CLI Tool executable path here
export TOOL_PATH=../../../../binaries/tmp

# Set the smcom here
export SMCOM=t1oi2c

# Set port name here
export PORT=/dev/i2c-1

# Set secure tunneling type here
export SECURE_TUNNELING=ntag_aes128_ev2

# Set your preferred key ID here
export KEY_ID=0x02

# Uncomment the curve type here and comment the rest
export KEY_CURVE_TYPE=prime256v1
# export KEY_CURVE_TYPE=brainpoolP256r1

# Uncomment the required auth type and comment the rest
# export AUTH=none
export AUTH=symmetric
# export AUTH=sigma_i_verifier
# export AUTH=sigma_i_prover

# Uncomment the curve type for authentication and comment the rest (not used in case of symmetric auth or auth none)
export AUTH_CURVE=prime256v1
# export AUTH_CURVE=brainpoolP256r1

# Set repo ID here
export REPO_ID=0x01

# Set input key path here
if ["$KEY_CURVE_TYPE" == "prime256v1"]; then
	export PRIV_KEY_PATH=input/nist_p256_keypair.pem
	export PUB_KEY_PATH=input/nist_p256_pubkey.pem
else 
	export PRIV_KEY_PATH=input/bp256_keypair.pem
	export PUB_KEY_PATH=input/bp256_pubkey.pem
fi

# Set input/output file path here
export INPUT_FILE=input/input_file.txt
export DIGEST_FILE=output/digest_out.txt
export SIGNATURE_FILE=output/signature_out.txt

# ######################################## ECDSA SCRIPT BEGINS HERE ########################################

if [ $AUTH == symmetric ]
then
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn $SECURE_TUNNELING -keyid 0x00
elif [ $AUTH == none ]
then
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn none -keyid 0x00
else
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn $SECURE_TUNNELING -curve $AUTH_CURVE -repoid $REPO_ID
fi

$TOOL_PATH/nxclitool setkey -keyid $KEY_ID -curve $KEY_CURVE_TYPE -in $PRIV_KEY_PATH -enable sign -waccess 0x0E
$TOOL_PATH/nxclitool dgst-sha256 -in $INPUT_FILE -out $DIGEST_FILE 
$TOOL_PATH/nxclitool dgst-sign -keyid $KEY_ID -in $DIGEST_FILE -out $SIGNATURE_FILE 
$TOOL_PATH/nxclitool dgst-verify -curve $KEY_CURVE_TYPE -pubkey $PUB_KEY_PATH -signature $SIGNATURE_FILE -in $DIGEST_FILE

$TOOL_PATH/nxclitool disconnect
