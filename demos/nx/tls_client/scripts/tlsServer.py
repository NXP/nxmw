#
# Copyright 2013 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
#

import subprocess
import sys
import logging
import time
import os
log = logging.getLogger(__name__)

DEFAULT_CIPHER_TYPE = "ECDHE"
DEFAULT_KEY_TYPE = "prime256v1"

def usage():
    log.info("Please provide as arguments as:  <cipher_type>[ECDHE(default)|ECDHE_SHA256|max]  <key_type>[prime256v1(default)|brainpoolP256r1]")
    log.info("Usage Example:")
    log.info("               python %s ECDHE brainpoolP256r1" % (__file__,))
    log.info("               python %s ECDHE_SHA256 prime256v1" % (__file__,))
    exit()

if __name__ == '__main__':
    logging.basicConfig(format='%(message)s', level=logging.DEBUG)

    cipher_type = DEFAULT_CIPHER_TYPE
    key_type = DEFAULT_KEY_TYPE

    if len(sys.argv) > 2:
        cipher_type = sys.argv[1]
        key_type = sys.argv[2]
    else:
        usage()

    if cipher_type == "ECDHE":
        sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA"
    elif cipher_type == "ECDHE_SHA256":
        sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA256"
    elif cipher_type == "max":
        sel_cipher="-cipher ECDHE-ECDSA-AES128-SHA,ECDHE-ECDSA-AES128-SHA256"
    else:
        log.info("Usage: tlsServer.py [ECDHE|ECDHE_SHA256|max|RSA]")
        exit()

    if key_type not in ["prime256v1", "brainpoolP256r1"]:
        usage()

    cur_dir = os.path.abspath(os.path.dirname(__file__))

    rootca_key = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_rootca_key.pem')
    rootca_cer = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_rootca.cer')

    server_key = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_server_key.pem')
    server_csr = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_server.csr')
    server_cer = os.path.join(cur_dir, '..', 'credentials', key_type, 'tls_server.cer')


    print("Ensure OPENSSL_CONF is not set to use OpenSSL engine")
    print("****************************************************")

#
# Invoke openssl s_server with additional parameters for more info
# -msg   : show all protocol messages with hex dump
# -debug : print extensive debugging information including a hex dump of all traffic
#

    if sys.platform.startswith("win"):
        openssl = os.path.join(cur_dir, '..', '..', '..', '..', 'ext', 'openssl', 'bin', 'openssl.exe')
    else:
        openssl = 'openssl'

    named_curve = f"-named_curve {key_type}"

    TLS_OPTION="tls1_3"
    if key_type == "brainpoolP256r1":
        TLS_OPTION="tls1_2"

    cmd=f"{openssl} s_server -accept 8080 -{TLS_OPTION} -CAfile {rootca_cer} -cert {server_cer} -key {server_key} {sel_cipher} {named_curve} -Verify 2 -debug -msg"
    log.info(cmd)
    p = subprocess.check_call(cmd, shell=True)
