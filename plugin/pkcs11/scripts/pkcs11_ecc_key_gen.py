#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""
Generates keys of type ECC
"""

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    keys = {"EC:prime256v1":"0x10000002",
            "EC:brainpoolP256r1":"0x10000003"}

    for key_type in keys:
        log.info("Generating keypair: %s" % (key_type))
        run("%s --module %s --keypairgen --key-type  %s --label sss:%s" % (pkcs11_tool, module_path, key_type, keys[key_type]))
        log.info("###################################################")


    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()