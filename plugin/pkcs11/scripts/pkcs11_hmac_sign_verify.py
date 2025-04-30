#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
"""

Generates generic key and performs hmac sign and verify operations

"""

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    obj_type = "secrkey"
    filename = "secr_key_16.key"
    key_type = "GENERIC:16"
    file_dir = key_dir + os.sep + filename
    log.info("Importing key: %s", file_dir)
    # set hmac key
    run("%s --module %s --write-object  %s --type %s --key-type  %s --label sss:0x40000010" % (pkcs11_tool, module_path, file_dir, obj_type, key_type))
    log.info("###################################################")

    sha_types = ["SHA256-HMAC"]
    for sha_type in sha_types:
        log.info("Signing data with length = 10 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --sign --mechanism %s --id 40000010 --input-file %sdata10.txt -o %sout_%s_input_10_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")

        log.info("Verifying data with length = 10 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --verify --mechanism %s --id 40000010 --input-file %sdata10.txt --signature-file %sout_%s_input_10_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")


        log.info("Signing data with length = 1024 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --sign --mechanism %s --id 40000010 --input-file %sdata1024.txt -o %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")

        log.info("Verifying data with length = 1024 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --verify --mechanism %s --id 40000010 --input-file %sdata1024.txt --signature-file %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")


        log.info("Signing data with length = 2048 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --sign --mechanism %s --id 40000010 --input-file %sdata2048.txt -o %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")

        log.info("Verifying data with length = 2048 and with key: %s and algo: %s" % (filename, sha_type))
        run("%s --module %s --verify --mechanism %s --id 40000010 --input-file %sdata2048.txt --signature-file %sout_%s_input_600_hmac.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type))
        log.info("###################################################")


    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()