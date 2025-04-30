#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
"""

Generates keys of type ECC and performs sign and verify operations

"""

from pkcs11_utils import *

def main():
    args = parse_in_ec_args()
    if args is None:
        return
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    log.info("Generating keypair: %s" % (args.key_type))
    run("%s --module %s --keypairgen --key-type  %s --label sss:0x10000002" % (pkcs11_tool, module_path, args.key_type))
    log.info("###################################################")


    data_len = ["32"]
    for len in data_len:
        log.info("Signing data with length %s and with key: %s and algo: ECDSA" % (len, args.key_type))
        run("%s --module %s --sign --mechanism ECDSA --id 10000002 --input-file %sdata%s.txt -o %sout_ECDSA_input_%s_%s.sign" % (pkcs11_tool, module_path, input_dir, len, output_dir, len, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length %s and with key: %s and algo: ECDSA" % (len, args.key_type))
        run("%s --module %s --verify --mechanism ECDSA --id 10000002 --input-file %sdata%s.txt --signature-file %sout_ECDSA_input_%s_%s.sign" % (pkcs11_tool, module_path, input_dir, len, output_dir, len, args.key_type.split(":")[1]))
        log.info("###################################################")


    sha_types = ["ECDSA-SHA256"]
    for sha_type in sha_types:
        log.info("Signing data with length = 600 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --sign --mechanism %s --id 10000002 --input-file %sdata600.txt -o %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 600 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --id 10000002 --input-file %sdata600.txt --signature-file %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Signing data with length = 2048 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --sign --mechanism %s --id 10000002 --input-file %sdata2048.txt -o %sout_%s_input_2048_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 2048 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --id 10000002 --input-file %sdata2048.txt --signature-file %sout_%s_input_2048_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()