# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause

# This script set config i2c management SA
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

#  Set your preferred i2c support here
export I2C_SUPPORT=0x01

#  Set i2c address here
export I2C_ADDRESS=0x20

#  Set protocolOptions here
export PROTOCOL_OPTIONS=0x1B85

# ######################################## GET UID SCRIPT BEGINS HERE ########################################

if [ $AUTH == symmetric ]
then
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn $SECURE_TUNNELING -keyid 0x00
elif [ $AUTH == none ]
then
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn none -keyid 0x00
else
$TOOL_PATH/nxclitool connect -smcom $SMCOM -port $PORT -auth $AUTH -sctunn $SECURE_TUNNELING -curve $AUTH_CURVE -repoid $REPO_ID
fi

$TOOL_PATH/nxclitool set-i2c_mgnt -i2csupport $I2C_SUPPORT -i2caddr $I2C_ADDRESS -protocoloptions $PROTOCOL_OPTIONS

$TOOL_PATH/nxclitool disconnect