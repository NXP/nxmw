# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

# This script creates a standard data file inside SA, lists out the file IDs present and writes
# some data in the created file. It then reads the file and stores the data in an output file.
# Before running this script, ensure a data file is present at the path specified at INPUT_DATA_PATH
# to be imported in the SA.
# Before running the script, ensure that the values of variables below are correct as per the use case.

# ######################################## SET VARIABLE VALUES ########################################

set -x

# Change the NX CLI Tool executable path here
export TOOL_PATH=../../../../binaries/tmp

# Set the smcom here
export SMCOM=t1oi2c

# Set port name here
export PORT=/dev/i2c-1

# Set secure tunneling type here
export SECURE_TUNNELING=ntag_aes128_ev2

# Set your preferred key ID here
export FILE_ID=0x04

# Set standard data file size (file inside SA) here
export FILE_SIZE=100

# Set number of bytes to read/write here
export BYTES=10

# Set data offset here
export OFFSET=5


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
export INPUT_DATA_PATH=input/data_in.txt
if [ -d "output" ]; then
    echo "output path exists"
else
    mkdir output
fi
export OUTPUT_DATA_PATH=output/data_out.txt

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

$TOOL_PATH/nxclitool create-bin -id $FILE_ID -bytes $FILE_SIZE -raccess 0x0E -waccess 0x0E -rwaccess 0x0E -caccess 0x0E -fcomm full

$TOOL_PATH/nxclitool list-fileid

$TOOL_PATH/nxclitool setbin -id $FILE_ID -bytes $BYTES -offset $OFFSET -in $INPUT_DATA_PATH

$TOOL_PATH/nxclitool getbin -id $FILE_ID -bytes $BYTES -offset $OFFSET -out $OUTPUT_DATA_PATH

$TOOL_PATH/nxclitool disconnect