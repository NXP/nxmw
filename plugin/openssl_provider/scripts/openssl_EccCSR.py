#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""


Generating CSR and Certificate with OpenSSL provider using EC Keys

This example showcases to generate CSR and Certificate using reference key.

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
        help='Parameter to decide which curve type of the key used to generate csr => eg. ``brainpoolP256r1``,``prime256v1``. Default: ``prime256v1``')

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
    rootca_type = output_dir + os.sep + args.key_type + ".pem"
    rootca_key = output_dir + os.sep + "rootca_key.pem"
    rootca_cer = output_dir + os.sep + "rootca.cer"

    output_csr = output_dir + os.sep + "0x2.csr"
    output_crt = output_dir + os.sep + "0x2.crt"
    ref_ec_key_0x2 = keys_dir + os.sep + "ecc_ref_key_0x2.pem"

    subject = "-subj \"/C=11/ST=111/L=111/O=NXP/OU=NXP/CN=example.com\""

    log.info("\n########### Create CA root key and certificates using openssl ###############")
    run("%s ecparam -name %s -out %s" %(openssl, args.key_type, rootca_type))
    run("%s ecparam -in %s -genkey -noout -out %s" %(openssl, rootca_type, rootca_key))
    if sys.platform.startswith("win"):
        run("%s req -x509 -new -nodes -key %s -subj \"/OU=NXP Plug Trust CA/CN=NXP RootCAvExxx\" -days 4380 -out %s -config %s " %(openssl, rootca_key, rootca_cer, conf_file))
    else:
        run("%s req -x509 -new -nodes -key %s -subj \"/OU=NXP Plug Trust CA/CN=NXP RootCAvExxx\" -days 4380 -out %s " %(openssl, rootca_key, rootca_cer))

    log.info("\n########### Generate EC Keys Using Openssl Provider at 0x2 location ###############")
    run("%s ecparam --provider %s --provider default -name %s:0x2 -genkey -out %s -propquery '?provider=nxp_prov'" %(openssl, provider, args.key_type, ref_ec_key_0x2))

    log.info("\n########### Create CSR and Certificate for ket at location 0x2 using openssl provider ###############")
    if sys.platform.startswith("win"):
        run("%s req -new --provider %s --provider default -key %s -out %s %s -propquery '?provider=nxp_prov' -config %s " %(openssl, provider, ref_ec_key_0x2, output_csr, subject, conf_file))
    else: 
        run("%s req -new --provider %s --provider default -key %s -out %s %s -propquery '?provider=nxp_prov'" %(openssl, provider, ref_ec_key_0x2, output_csr, subject))

    run("%s x509 -req --provider %s --provider default -in %s -CAcreateserial -out %s -days 5000 -CA %s -CAkey %s -propquery '?provider=nxp_prov'" %(openssl, provider, output_csr, output_crt, rootca_cer, rootca_key))
    run("%s x509 -in %s -text -noout" %(openssl, output_crt))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()