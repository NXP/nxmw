#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""

Validation of Sign Verify with OpenSSL provider using EC Keys

This example showcases sign using reference key, then verify using openssl and vice versa.

Precondition:
    - Inject keys using ``ex_provider_provision_key.c``.

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

    SIGNATURE_0 = output_dir + os.sep + "signature_hash_0.bin"
    SIGNATURE_1 = output_dir + os.sep + "signature_dgst_1.bin"

    SIGN_KEY = keys_dir + os.sep + f"ecc_key_kp.pem"
    VERIFY_KEY = keys_dir + os.sep + f"ecc_key_public.pem"
    SIGN_REF_KEY = keys_dir + os.sep + f"ecc_key_kp_ref_keyid_02.pem"

    TO_SIGN = cur_dir + os.sep + "input_data" + os.sep + "input_data_100_bytes.txt"
    TO_SIGN_32_Bytes=cur_dir + os.sep + "input_data" + os.sep + "input_data_32_bytes.txt"
    TO_SIGN_1024_Bytes=cur_dir + os.sep + "input_data" + os.sep + "input_data_1024_bytes.txt"

    log.info("\n######### Positive Signature test cases using key labels ##########")
    log.info("################################################## \n")

    log.info("Sign using Provider (Using key labels) ")
    run("%s pkeyutl --provider %s --provider default -inkey nxp:0x02 -sign -rawin -in %s -out %s -digest sha256" % (openssl, provider, TO_SIGN, SIGNATURE_0))
    log.info("###################################################")
    log.info("Verify signature using host ")
    run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest sha256"%(openssl,VERIFY_KEY,SIGNATURE_0,TO_SIGN))
    log.info("#################################################### \n")

    log.info("Sign using Provider (Using key labels)  (1024 Bytes data) ")
    run("%s pkeyutl --provider %s --provider default -inkey nxp:0x02 -sign -rawin -in %s -out %s -digest sha256" % (openssl, provider, TO_SIGN_1024_Bytes, SIGNATURE_0))
    log.info("###################################################")
    log.info("Verify signature using host  ")
    run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest sha256"%(openssl,VERIFY_KEY,SIGNATURE_0,TO_SIGN_1024_Bytes))
    log.info("#################################################### \n")

    log.info("Verify signature using Provider Host Implementation")
    run("%s pkeyutl --provider %s --provider default -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest sha256"%(openssl, provider,VERIFY_KEY,SIGNATURE_0,TO_SIGN_1024_Bytes))
    log.info("#################################################### \n")


    log.info("######### Positive Signature test cases by passing reference keys ##########")
    log.info("##################################################\n")

    log.info("Sign using Provider (Using reference keys) ")
    run("%s pkeyutl --provider %s --provider default -inkey %s -sign -rawin -in %s -out %s -digest sha256 -propquery 'provider=nxp_prov'" % (openssl, provider, SIGN_REF_KEY, TO_SIGN, SIGNATURE_0))
    log.info("###################################################")
    log.info("Verify signature using host")
    run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest sha256"%(openssl,VERIFY_KEY,SIGNATURE_0,TO_SIGN))
    log.info("#################################################### \n")


    log.info("Sign using Provider (Using key labels) on hash data - 32 Bytes ")
    run("%s pkeyutl --provider %s --provider default -inkey nxp:0x02 -sign -in %s -out %s" % (openssl, provider, TO_SIGN_32_Bytes, SIGNATURE_0))
    log.info("###################################################")
    log.info("Verify signature using host  ")
    run("%s pkeyutl -inkey %s -pubin -verify -in %s -sigfile %s" % (openssl, VERIFY_KEY, TO_SIGN_32_Bytes, SIGNATURE_0))
    log.info("#################################################### \n")

    log.info("Sign using Provider Host (Using key labels) on hash data - 32 Bytes ")
    run("%s pkeyutl --provider %s --provider default -inkey %s -sign -in %s -out %s -propquery 'provider=nxp_prov'" % (openssl, provider, SIGN_KEY, TO_SIGN_32_Bytes, SIGNATURE_0))
    log.info("###################################################")
    log.info("Verify signature using host  ")
    run("%s pkeyutl -inkey %s -pubin -verify -in %s -sigfile %s" % (openssl, VERIFY_KEY, TO_SIGN_32_Bytes, SIGNATURE_0))
    log.info("#################################################### \n")

    log.info("Verify signature using Provider Host Implementation")
    run("%s pkeyutl --provider %s --provider default -inkey %s -pubin -verify -in %s -sigfile %s" % (openssl, provider, VERIFY_KEY, TO_SIGN_32_Bytes, SIGNATURE_0))
    log.info("#################################################### \n")


    log.info("######### Positive Signature test cases by passing keypair ##########")
    log.info("##################################################\n")
    log.info("Sign using Provider (Using reference keys) ")
    run("%s pkeyutl --provider %s --provider default -inkey %s -sign -rawin -in %s -out %s -digest sha256 -propquery 'provider=nxp_prov'" % (openssl, provider, SIGN_KEY, TO_SIGN, SIGNATURE_0))
    log.info("###################################################")
    log.info("Verify signature using host")
    run("%s pkeyutl -verify -pubin -inkey %s -sigfile %s -in %s -rawin -digest sha256"%(openssl,VERIFY_KEY,SIGNATURE_0,TO_SIGN))
    log.info("#################################################### \n")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()