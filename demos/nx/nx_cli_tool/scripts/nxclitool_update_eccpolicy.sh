# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

# This script update ecc key policy SA
# Before running the script, ensure that the values of variables below are correct as per the use case.

# ######################################## SET VARIABLE VALUES ########################################

set -x

# Change the NX CLI Tool executable path here
export TOOL_PATH=../../../../binaries/tmp

# Set the smcom here
export SMCOM=t1oi2c

# Set port name here
export PORT=/dev/i2c-1

# Set the key ID here for key generation
export KEY_ID=0x00

# Set secure tunneling type here
export SECURE_TUNNELING=ntag_aes128_ev2

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
export REPO_ID=0x00

# ECC Key Policy Flags
# FLAG_SIGMA_I=0x0004
# FLAG_ECDH=0x0008
# FLAG_ECC_SIGN=0x0010
# FLAG_SDM=0x0020
# FLAG_CARD_UNILATERAL_AUTH=0x0100
# FLAG_KEY_USEAGE_CTR_LIMIT=0x8000

# Set combined ECC key policy flags in hex.
# e.g ecc sign and sigma-i, 0x0010 + 0x0004 = 0x0014
export UPDATE_ECCKEY_POLICY=0x0014

# Set KeyusageCtrLimit
export KEY_USAGE_CTR_LIMIT=0x00000000

# ######################################## UPDATE ECC POLICY SCRIPT BEGINS HERE ########################################

if [ $AUTH == symmetric ]
then
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn $SECURE_TUNNELING -keyid 0x00
elif [ $AUTH == none ]
then
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn none -keyid 0x00
else
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn $SECURE_TUNNELING -curve $AUTH_CURVE -repoid $REPO_ID
fi

$TOOL_PATH/nxclitool update-eccpolicy -keyid $KEY_ID -keypolicy $UPDATE_ECCKEY_POLICY -wcomm full -waccess 0x00 -kuclimit $KEY_USAGE_CTR_LIMIT

$TOOL_PATH/nxclitool disconnect

