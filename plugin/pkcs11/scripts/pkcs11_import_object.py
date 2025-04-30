#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
"""

Creates objects (Certificate, Public key and Private key)

"""

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    obj_type = "cert"
    file_name = "test_certificate.der"
    file_dir = key_dir + os.sep + file_name

    log.info("Importing certificate into SE: %s" % (file_name))
    run("%s --module %s --write-object %s --type  %s --label sss:0x20000005" % (pkcs11_tool, module_path, file_dir, obj_type))
    log.info("###################################################")

    log.info("Reading certificate object: %s" % (file_name))
    run("%s --module %s --read-object --type %s --label sss:0x20000005 -o %s%s" % (pkcs11_tool, module_path, obj_type, output_dir, file_name))
    log.info("###################################################")

    obj_type = "cert"
    file_name = "demo_cert.pem"
    file_dir = key_dir + os.sep + file_name

    log.info("Importing certificate into SE: %s" % (file_name))
    run("%s --module %s --write-object %s --type  %s --label sss:0x20000004" % (pkcs11_tool, module_path, file_dir, obj_type))
    log.info("###################################################")

    log.info("Reading certificate object: %s" % (file_name))
    run("%s --module %s --read-object --type %s --label sss:0x20000004 -o %s%s" % (pkcs11_tool, module_path, obj_type, output_dir, file_name))
    log.info("###################################################")

    prime_type = ["prime256"]
    for prime in prime_type:

        obj_type = "privkey"
        file_name = "ec_%s_priv.pem" % (prime)
        file_dir = key_dir + os.sep + file_name

        log.info("Importing ECC Private key object: %s" % (file_name))
        run("%s --module %s --write-object %s --type  %s --label sss:0x10000002" % (pkcs11_tool, module_path, file_dir, obj_type))
        log.info("###################################################")

        obj_type = "pubkey"
        file_name = "ec_%s_pub.pem" % (prime)
        file_dir = key_dir + os.sep + file_name

        log.info("Importing ECC Public key object: %s" % (file_name))
        run("%s --module %s --write-object %s --type  %s --label sss:0x10000002" % (pkcs11_tool, module_path, file_dir, obj_type))
        log.info("###################################################")

    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()