#
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

import logging
import os
import subprocess
import sys
import traceback
from subprocess import Popen, PIPE, CalledProcessError

logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)
cur_dir = os.path.abspath(os.path.dirname(__file__))

ecc_types = [
    "prime256v1",
    "brainpoolP256r1",
]

ecc_types_cryptography_44 = [
    "prime256v1",
    "brainpoolP256r1",
]

def isValidKeyType(keyType):
    if keyType in ecc_types :
        return True
    return False

def run(cmd_str, ignore_result=0, exp_retcode=0):
    print("Running command: %s" %cmd_str)
    with Popen(cmd_str, stdout=PIPE, bufsize=1, universal_newlines=True, shell=True) as p:
        for line in p.stdout:
            print(line, end='') # process line here
    if p.returncode != 0:
        raise CalledProcessError(p.returncode, p.args)

def compare(input_file, decrypt_file):
    with open(input_file, 'rb') as raw_data:
        in_data = raw_data.read()

    with open(decrypt_file, 'rb') as decrypt_data:
        dec_data = decrypt_data.read()

    assert in_data == dec_data

    raw_data.close()
    decrypt_data.close()


