#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Performs Encryption/Decryption
"""
import binascii
import sys

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    log.info("Generating symmetric key: aes:16.. (Generates random data and set key)")
    run("%s --module %s --keygen --key-type aes:16 --label sss:0x40000010" % (pkcs11_tool, module_path))
    log.info("###################################################")

    mechanisms = ["aes-ecb", "aes-cbc"]
    for mech in mechanisms:
        log.info("Performing encryption operation")
        run("%s --module %s --encrypt --id 40000010 --mechanism %s --input-file %sdata10.txt --output-file %sencrypted_%s.txt" % (pkcs11_tool, module_path, mech, input_dir, output_dir, mech))
        log.info("###################################################")

        log.info("Performing decryption operation")
        run("%s --module %s --decrypt --id 40000010 --mechanism %s --input-file %sencrypted_%s.txt --output-file %sdecrypted_%s.txt" % (pkcs11_tool, module_path, mech, output_dir, mech, output_dir, mech))
        log.info("###################################################")

   
    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()