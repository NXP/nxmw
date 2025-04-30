#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
"""

Generates digest of some data using different algorithms

"""

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    log.info("login command")
    run("%s --module %s -O --login --pin 1" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()
