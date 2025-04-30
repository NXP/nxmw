#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Generates symmetric key of type AES
"""

from pkcs11_utils import *

def main():
    keys = ["aes:16", "aes:32"]
    for key in keys:
        log.info("Generating symmetric key: %s.. (Generates random data and set key)" % (key))
        run("%s --module %s --keygen --key-type %s --label sss:0x40000010" % (pkcs11_tool, module_path, key))
        log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()