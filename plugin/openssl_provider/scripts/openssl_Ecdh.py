#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""

This example showcases ECDH between openssl provider and openssl.

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

    KEYPAIR_0 = keys_dir + os.sep + f"ecc_key_kp.pem"

    PUBKEY_0 = keys_dir + os.sep + "ecc_key_pub_pubonly_0.pem"

    REF_KEY_0 = keys_dir + os.sep + "ecc_key_kp_ref_keyid_04.pem"

    SHARED_SECRET_HOST_0 = output_dir + os.sep + "ecdh_host_0.bin"
    SHARED_SECRET_provider_0 = output_dir + os.sep + "ecdh_provider_0.bin"


    log.info("############### ECDH by using key labels in Provider ####################\n")

    log.info("############## Do ECDH on host ###############")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl, KEYPAIR_0, PUBKEY_0, SHARED_SECRET_HOST_0))
    log.info("############## Do ECDH with provider (using key labels) ##########")
    run("%s pkeyutl -derive --provider %s --provider default -inkey nxp:0x04 -peerkey %s -hexdump -out %s" %(openssl, provider, PUBKEY_0, SHARED_SECRET_provider_0))
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_provider_0)
    log.info("#######################################################\n")
    log.info("############## Do ECDH on Provider host implementation ###############")
    run("%s pkeyutl --provider %s --provider default -inkey %s -peerkey %s -derive -hexdump -out %s -propquery 'provider=nxp_prov'" % (openssl, provider, KEYPAIR_0, PUBKEY_0, SHARED_SECRET_HOST_0))

    log.info("############### ECDH by passing refernce keys to Provider ####################\n")

    log.info("############## Do ECDH on host ###############")
    run("%s pkeyutl -inkey %s -peerkey %s -derive -hexdump -out %s" % (openssl,  KEYPAIR_0,  PUBKEY_0, SHARED_SECRET_HOST_0))
    log.info("############## Do ECDH with provider (using reference keys) ##########")
    run("%s pkeyutl -derive --provider %s --provider default -inkey %s -peerkey %s -hexdump -out %s -propquery 'provider=nxp_prov'" %(openssl, provider, REF_KEY_0, PUBKEY_0, SHARED_SECRET_provider_0))
    compare(SHARED_SECRET_HOST_0, SHARED_SECRET_provider_0)
    log.info("#######################################################\n")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()