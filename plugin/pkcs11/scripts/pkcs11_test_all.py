#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

import argparse
from pkcs11_utils import *

def main():
	run("python3 pkcs11_import_object.py" )
	run("python3 pkcs11_message_digest.py")
	run("python3 pkcs11_ecc_key_gen.py" )
	run("python3 pkcs11_ecc_sign_verify.py --key_type EC:prime256v1" )
	run("python3 pkcs11_ecc_sign_verify.py --key_type EC:brainpoolP256r1" )
	run("python3 pkcs11_module_info.py" )
	run("python3 pkcs11_misc_tests.py" )
	run("python3 pkcs11_random_gen.py" )
	run("python3 pkcs11_sym_key_gen.py" )
	run("python3 pkcs11_encrypt_decrypt.py" )
	run("python3 pkcs11_hmac_sign_verify.py" )

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
