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

    log.info("Digest with SHA256")
    run("%s --module %s --hash --mechanism SHA256 --input-file %sdata1024.txt --output-file %sout_hash_sha256.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    log.info("Digest with SHA384")
    run("%s --module %s --hash --mechanism SHA384 --input-file %sdata600.txt --output-file %sout_hash_sha384.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    log.info("Digest with SHA256")
    run("%s --module %s --hash --mechanism SHA256 --input-file %sdata2048.txt --output-file %sout_hash_data2048.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    log.info("Digest with SHA256")
    run("%s --module %s --hash --mechanism SHA256 --input-file %sdata64.txt --output-file %sout_hash_data64.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")



    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()
