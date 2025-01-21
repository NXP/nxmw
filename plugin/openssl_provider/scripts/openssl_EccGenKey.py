#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

import argparse

from openssl_util import *

log = logging.getLogger(__name__)

example_text = '''

Example invocation::

    python %s --key_type brainpoolP256r1
    python %s --key_type prime256v1 --connection_data "NXP Semiconductors P71 T=0, T=1 Driver 0"

''' % (__file__,  __file__, )

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
    key_type = sys.argv[2]
    key_type_keyid = key_type+":0x03"
    output_dir = cur_dir + os.sep + "output"
    output_keys_dir = cur_dir + os.sep + "output" + os.sep + key_type

    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    if not os.path.exists(output_keys_dir):
        os.mkdir(output_keys_dir)

    ref_ec_key_default = output_keys_dir + os.sep + "ecc_ref_key_default.pem"
    ref_ec_key_0x03 = output_keys_dir + os.sep + "ecc_ref_key_0x03.pem"

    log.info("\n########### Generate EC Keys Using Openssl Provider at default location (0x04) ###############")
    run("%s ecparam --provider %s --provider default -name %s -genkey -out %s -propquery 'provider=nxp_prov'" %(openssl, provider, key_type, ref_ec_key_default))

    log.info("\n########### Generate EC Keys Using Openssl Provider at 0x03 location ###############")
    run("%s ecparam --provider %s --provider default -name %s -genkey -out %s -propquery 'provider=nxp_prov'" %(openssl, provider, key_type_keyid, ref_ec_key_0x03))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
