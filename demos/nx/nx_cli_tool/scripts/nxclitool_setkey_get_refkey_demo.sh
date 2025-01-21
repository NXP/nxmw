# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

# This script sets a private key using the NX CLI Tool on Linux platform
# Before running this script, ensure a key is present in PEM format at the path specified in PRIV_KEY_PATH to be imported in the SA.
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
export CURVE=prime256v1
# export CURVE=brainpoolP256r1

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
export PRIV_KEY_PATH=input/nist_p256_keypair.pem
export PUB_KEY_PATH=input/nist_p256_pubkey.pem

# ######################################## GENERATION SCRIPT BEGINS HERE ########################################

if [ $AUTH == symmetric ]
then
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn $SECURE_TUNNELING -keyid 0x00
elif [ $AUTH == none ]
then
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn none -keyid 0x00
else
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn $SECURE_TUNNELING -curve $AUTH_CURVE -repoid $REPO_ID
fi

$TOOL_PATH/nxclitool setkey -keyid $KEY_ID -curve prime256v1 -in $PRIV_KEY_PATH -enable sign

$TOOL_PATH/nxclitool disconnect

$TOOL_PATH/nxclitool get-ref-key -keyid $KEY_ID -in $PUB_KEY_PATH -out output/ref.key