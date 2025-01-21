#
# Copyright 2023 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""

Generate few random numbers from the attached Secure Authenticator.

"""

import argparse

from openssl_util import *

example_text = '''

Example invocation::

    python %s --connection_data COM4
    python %s --connection_data "NXP Semiconductors P71 T=0, T=1 Driver 0"

''' % (__file__,__file__,)


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
        help='Parameter to connect to SE => eg. ``COM3``, ``NXP Semiconductors P71 T=0, T=1 Driver 0``, ``none``. Default: ``none``')

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

    run("%s rand -engine %s -hex 8" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 16" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 32" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 64" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 128" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 256" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 384" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 512" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 748" % (openssl, openssl_engine))
    run("%s rand -engine %s -hex 5000" % (openssl, openssl_engine))

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#     Program completed successfully                         #")
    log.info("#                                                            #")
    log.info("##############################################################")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
