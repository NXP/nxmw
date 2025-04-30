#
# Copyright 2025 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

import os
import sys
from utils import *

server_address = "localhost"

keyTypeMap = {
    'prime256v1':'secp256r1',
    'brainpoolP256r1':'brainpoolP256r1',
}

def printUsage():
    print('Invalid input argument')
    print('Run as -  start_ssl2_client.py  <keyType> <cipher_suite>')
    print('supported key types -')
    print(keyTypeMap)
    print('Example invocation - start_ssl2_client.py prime256v1 TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA')
    print('Example invocation - start_ssl2_client.py brainpoolP256r1 TLS-ECDH-ECDSA-WITH-AES-128-CBC-SHA')
    sys.exit()


if len(sys.argv) != 3:
    printUsage()
else:
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    keytype = sys.argv[1]
    cipher_suite = sys.argv[2];
    if isValidKeyType(keytype) != True:
        printUsage()
    mbedtls_keyType = keyTypeMap[keytype]
    curves = ""
    if isValidKeyType(keytype) == True:
        curves = "curves=" + mbedtls_keyType

    tls_rootCA = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_rootca.cer')
    tls_client_cert = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client.cer')
    tls_client_ref_key = os.path.join(cur_dir, '..', 'keys', keytype, 'tls_client_key_ref.pem')

    mbedtls_client = os.path.join(cur_dir, '..', '..',  '..', 'tools', 'mbedtls_3x_client')
    run("%s server_name=%s exchanges=1 force_version=tls12 debug_level=1 ca_file=%s auth_mode=required key_file=%s crt_file=%s force_ciphersuite=%s"
        %(mbedtls_client, server_address, tls_rootCA, tls_client_ref_key, tls_client_cert, cipher_suite))
