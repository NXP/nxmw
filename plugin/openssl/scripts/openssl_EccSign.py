#
# Copyright 2023-2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""

Validation of Sign Verify with OpenSSL engine using EC Keys

This example showcases sign using reference key, then verify using openssl and vice versa.

Precondition:
    - Inject keys using ``ex_engine_provision_key.c``.

"""
import argparse

from openssl_util import *

log = logging.getLogger(__name__)

example_text = '''
############################################################################################################

Invocation format::
    python %s --connection_data {COM7|"NXP Semiconductors P71 T=0, T=1 Driver 0"} --key_type {prime256v1|brainpoolP256r1}

############################################################################################################

Invocation example::

    python %s --connection_data "NXP Semiconductors P71 T=0, T=1 Driver 0" --key_type brainpoolP256r1
    python %s --connection_data COM7 --key_type prime256v1

############################################################################################################
''' % (__file__, __file__, __file__)

def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument(
       '--connection_data',
       default="none",
       help='Parameter to connect NX IC => eg. ``COM3``,``NXP Semiconductors P71 T=0, T=1 Driver 0``. Default: ``none``,' )
    required.add_argument('--key_type',
        default="prime256v1",
        help='Parameter to decide which curve type of the key used to sign/verify => eg. ``brainpoolP256r1``,``prime256v1``. Default: ``prime256v1``')

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        return None;

    args = parser.parse_args()

    os.environ['EX_SSS_BOOT_SSS_PORT']=args.connection_data;
    log.info("EX_SSS_BOOT_SSS_PORT: %s" % args.connection_data)

    return args


def main():

    args = parse_in_args()

    if args is None:
        return

    if sys.platform.startswith("win"):
        keys_dir = os.path.join(cur_dir, '..', f'keys\\{args.key_type}',)
    else :
        keys_dir = os.path.join(cur_dir, '..', f'keys/{args.key_type}',)


    if not os.path.exists("output"):
        os.mkdir("output")

    output_dir = cur_dir + os.sep + "output"

    SIGN_KEY_REF = keys_dir + os.sep + f"ecc_key_kp_ref_keyid_02.pem"
    VERIFY_KEY_REF = keys_dir + os.sep + f"ecc_key_pub_ref_keyid_02.pem"

    SIGN_KEY = keys_dir + os.sep + f"ecc_key_kp.pem"
    VERIFY_KEY = keys_dir + os.sep + f"ecc_key_kp.pem"

    SIGNATURE_V = output_dir + os.sep + "signature_v_hash.bin"
    SIGNATURE = output_dir + os.sep + "signature_hash.bin"
    SIGNATURE_H = output_dir + os.sep + "signature_hash_host.bin"

    TO_SIGN = cur_dir + os.sep + '..' + os.sep + "readme.md"

    log.info("############################################################")
    log.info("Positive signing tests ")
    log.info("############################################################")

    log.info("\nSign the file with engine")
    run("%s dgst -engine %s -sha256 -sign %s -out %s %s "%(openssl, openssl_engine, SIGN_KEY_REF, SIGNATURE, TO_SIGN))

    log.info("\nNow verify the signature with Host")
    run("%s dgst -sha256 -prverify %s -signature %s %s" % (openssl, VERIFY_KEY, SIGNATURE, TO_SIGN))

    log.info("\nSign the file with Host" )
    run("%s dgst -sha256 -sign %s -out %s %s" % (openssl, SIGN_KEY, SIGNATURE_V, TO_SIGN))

    log.info("\nverify using engine")
    run("%s dgst -engine %s -sha256 -prverify %s -signature %s %s" %(openssl, openssl_engine, VERIFY_KEY_REF, SIGNATURE_V, TO_SIGN))

    log.info("\nSign the file using Engine Host Implementation" )
    run("%s dgst -engine %s -sha256 -sign %s -out %s %s" % (openssl, openssl_engine, SIGN_KEY, SIGNATURE_H, TO_SIGN))

    log.info("\nverify using engine")
    run("%s dgst -engine %s -sha256 -prverify %s -signature %s %s" %(openssl, openssl_engine, VERIFY_KEY_REF, SIGNATURE_H, TO_SIGN))

    log.info("\nSign the file with engine")
    run("%s dgst -engine %s -sha256 -sign %s -out %s %s "%(openssl, openssl_engine, SIGN_KEY_REF, SIGNATURE, TO_SIGN))

    log.info("\nNow verify the signature with Engine Host Implementation")
    run("%s dgst -engine %s -sha256 -prverify %s -signature %s %s" % (openssl, openssl_engine, VERIFY_KEY, SIGNATURE, TO_SIGN))



    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()