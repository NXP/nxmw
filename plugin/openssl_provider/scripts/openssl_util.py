#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

import logging
import os
import subprocess
import sys
import traceback

logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)
cur_dir = os.path.abspath(os.path.dirname(__file__))
py_sss_dir = os.path.join(cur_dir, '..', '..', '..', '..', 'pycli', 'src')
sys.path.append(py_sss_dir)

if sys.platform.startswith("win"):
    library_name = "sssProvider.dll"
    provider_path=os.path.join(cur_dir,'..','bin')
    provider=os.path.join(cur_dir,'..','bin',library_name)
    openssl = os.path.join(cur_dir, '..', '..', '..', 'ext', 'openssl-30', 'bin', 'openssl.exe')
    conf_file = os.path.join(cur_dir, '..', '..', '..', 'ext', 'openssl', 'ssl', 'openssl.cnf')
else:
    openssl = 'openssl'
    library_name = "libsssProvider.so"
    provider_path=os.path.join(cur_dir,'..','bin')
    provider=os.path.join(cur_dir,'..','bin',library_name)
    if "OPENSSL30_BINARY" in os.environ:
        openssl_bin = os.environ["OPENSSL30_BINARY"]
        print("\n Using OpenSSL from %s \n" %(openssl_bin))
    else:
        openssl_bin="openssl"

SUPPORTED_EC_KEY_TYPES = [
    "prime256v1",
    "brainpoolP256r1",
]

SUPPORTED_CONNECTION_TYPES = [
    "t1oi2c",
    "vcom",
    "pcsc"
]

def run(cmd_str, ignore_result=0, exp_retcode=0):
    log.info("")
    log.info("Running command:")
    log.info("%s" % (cmd_str,))
    pipes = subprocess.Popen(
        cmd_str,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )
    std_out, std_err = pipes.communicate()
    std_out = std_out.strip()
    std_err = std_err.strip()
    log.info("%s" % std_out.decode())
    if not ignore_result:
        print(pipes.returncode)
        if pipes.returncode != exp_retcode:
            log.error("ERROR: Return code: %s, Expected return code: %s " % (pipes.returncode, exp_retcode))
            log.error("ERROR: std_err: %s" % std_err.decode())
        else:
            log.info("Command execution was successful.")
        assert pipes.returncode == exp_retcode


def compare(input_file, decrypt_file):
    with open(input_file, 'rb') as raw_data:
        in_data = raw_data.read()

    with open(decrypt_file, 'rb') as decrypt_data:
        dec_data = decrypt_data.read()

    assert in_data == dec_data

    raw_data.close()
    decrypt_data.close()


