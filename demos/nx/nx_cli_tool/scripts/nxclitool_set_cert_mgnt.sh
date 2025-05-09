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

# Set leaf cache size here
export LEAF_CACHE_SIZE=0x08

# Set Intermediate certificate cache size here
export INTERM_CACHE_SIZE=0x08

# Set Enable SIGMA-I cache here
export ENABLE_SIGMA_I_CACHE=0x01
#export DISABLE_SIGMA_I_CACHE=0x00

# Set feature selection here
export FEATURE_SELECTION=$ENABLE_SIGMA_I_CACHE

# Set config cert management commMode here
export COMM_MODE=plain

# Set config cert management access condition here
export ACCESS_CONDITION=0x00


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

$TOOL_PATH/nxclitool set-cert_mgnt -leafcachesize $LEAF_CACHE_SIZE -intermcachesize $INTERM_CACHE_SIZE -featureselection $FEATURE_SELECTION -wcomm $COMM_MODE -waccess $ACCESS_CONDITION

$TOOL_PATH/nxclitool disconnect