#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""

Validation of ECDH with OpenSSL engine using EC keys

This example showcases ECDH between openssl engine and openssl.

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
        help='Parameter to decide which curve type of the key used to generate shared secret => eg. ``brainpoolP256r1``,``prime256v1``. Default: ``prime256v1``')
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

    KEYPAIR_REF = keys_dir + os.sep + f"ecc_key_kp_ref_keyid_03.pem"
    KEYPAIR = keys_dir + os.sep + f"ecc_key_kp.pem"
    PUBKEY = keys_dir + os.sep + f"ecc_key_pub.pem"

    SHARED_SECRET_ENGINE = output_dir + os.sep + "SHARED_SECRET_ENGINE.bin"
    SHARED_SECRET_HOST = output_dir + os.sep + "SHARED_SECRET_HOST.bin"

    log.info("Do ECDH on Engine")

    log.info("## Clean up etc.")
    log.info("######################################################")
    if sys.platform.startswith("win"):
        run("del -f %s" % (SHARED_SECRET_ENGINE,))

    log.info("######################################################")
    log.info("\nECDH with engine")
    run("%s pkeyutl -engine %s -inkey %s -peerkey %s -derive -hexdump -out %s" %(openssl, openssl_engine, KEYPAIR_REF, PUBKEY, SHARED_SECRET_ENGINE))

    log.info("######################################################")
    log.info("\nECDH with host")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl, KEYPAIR, PUBKEY, SHARED_SECRET_HOST))

    log.info("######################################################")
    log.info("\nECDH with Engine Host Implementation")
    run("%s pkeyutl -engine %s -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl, openssl_engine, KEYPAIR, PUBKEY, SHARED_SECRET_HOST))

    log.info("############################################")
    compare(SHARED_SECRET_ENGINE, SHARED_SECRET_HOST)

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
