#!/bin/sh
#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

# Determine directory where script is stored
AWS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo ${AWS_DIR}

cd ${AWS_DIR}/aws-iot-device-sdk-cpp
mkdir build
sed -i '31 a ADD_DEFINITIONS\(\-DOPENSSL_LOAD_CONF\)' CMakeLists.txt
cd  build
cmake ../.
make pub-sub-sample

cp -f ${AWS_DIR}/SampleConfig.json ${AWS_DIR}/aws-iot-device-sdk-cpp/build/bin/config
cp -f ${AWS_DIR}/AmazonRootCA1.pem ${AWS_DIR}/aws-iot-device-sdk-cpp/build/bin/certs
cp -f ${AWS_DIR}/aws_provisioning_client/credentials/nx_device_certificate.cer ${AWS_DIR}/aws-iot-device-sdk-cpp/build/bin/certs
cp -f ${AWS_DIR}/aws_provisioning_client/credentials/nx_device_key.pem ${AWS_DIR}/aws-iot-device-sdk-cpp/build/bin/certs
cp -f ${AWS_DIR}/aws_provisioning_client/credentials/nx_device_reference_key.pem ${AWS_DIR}/aws-iot-device-sdk-cpp/build/bin/certs