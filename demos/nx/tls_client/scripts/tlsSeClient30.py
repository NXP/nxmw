#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

import subprocess
import sys
import logging
import time
import os
log = logging.getLogger(__name__)

DEFAULT_IP_ADDRESS = "127.0.0.1"
DEFAULT_CIPHER_TYPE = "ECDHE"
DEFAULT_KEY_TYPE = "prime256v1"

def usage():
    log.info("Please provide arguments as:  <ip-address> <cipher_type>[ECDHE(default)|ECDHE_SHA256|max] <key_type>[prime256v1(default)|brainpoolP256r1]")
    log.info("Usage Example:")
    log.info("               python %s 127.0.0.1 ECDHE brainpoolP256r1" % (__file__,))
    log.info("               python %s 127.0.0.1 ECDHE_SHA256 prime256v1" % (__file__,))
    exit()

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level=logging.DEBUG)

    ip_addr = DEFAULT_IP_ADDRESS
    cipher_type = DEFAULT_CIPHER_TYPE
    key_type = DEFAULT_KEY_TYPE

    if len(sys.argv) > 3:
        ip_addr = sys.argv[1]
        cipher_type = sys.argv[2]
        key_type = sys.argv[3]
    else:
        usage()

    if cipher_type == "ECDHE":
        sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA"
    elif cipher_type == "ECDHE_SHA256":
        sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA256"
    elif cipher_type == "max":
        sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA,ECDHE-ECDSA-AES128-SHA256"
    else:
        usage()

    if key_type not in ["prime256v1", "brainpoolP256r1"]:
        usage()


    cur_dir = os.path.abspath(os.path.dirname(__file__))

    rootca_key = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_rootca_key.pem')
    rootca_cer = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_rootca.cer')

    client_key = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_client_key.pem')
    client_key_ref = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_client_key_ref.pem')
    client_key_pub = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_client_key_pub.pem') # Contains public key only
    client_csr = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_client.csr')
    client_cer = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_client.cer')

    print("Ensure OPENSSL_CONF is set to use sss based OpenSSL Provider")
    OPENSSL_CONF_SE="../../../linux/common/openssl30_sss_nx.cnf"
    print("export OPENSSL_CONF=",OPENSSL_CONF_SE)
    os.environ['OPENSSL_CONF'] = OPENSSL_CONF_SE


    if sys.platform.startswith("win"):
        library_name = "sssProvider.dll"
        openssl = os.path.join(cur_dir, '..', '..', '..', '..', 'ext', 'openssl-30', 'bin', 'openssl.exe')
        openssl_provider = os.path.join(cur_dir, '..', '..', '..', '..', 'plugin', 'openssl_provider', 'bin', library_name)
        provider_path = os.path.join(cur_dir, '..', '..', '..', '..', 'plugin', 'openssl_provider', 'bin')
    else:
        openssl = 'openssl'

    TLS_OPTION="tls1_3"
    if key_type == "brainpoolP256r1":
        TLS_OPTION="tls1_2"

    groups = f"-groups {key_type}"
    cmd=f"{openssl} s_client -connect {ip_addr}:8080 -{TLS_OPTION} -CAfile {rootca_cer} -cert {client_cer} -key nxp:{client_key_ref} {groups} {sel_cipher} -debug -msg"
    log.info(cmd)
    p = subprocess.check_call(cmd, shell=True)
