#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#
"""

Utility functions for PKCS11 testing scripts

"""
import argparse
import logging
import os
import subprocess
import sys
import traceback

logging.basicConfig(format='%(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)

example_text = '''
Example invocation::
    python3 %s --key_type EC:prime256v1
''' % (__file__)

example_ec_text = '''
Example invocation::
    python3 %s --key_type EC:prime256v1
''' % (__file__)

cur_dir = os.path.abspath(os.path.dirname(__file__))

# Update the library name here
library_name="libsss_pkcs11.so"
module_path=os.path.join('..','bin',library_name)
pkcs11_tool="pkcs11-tool"
input_dir = cur_dir + os.sep + "input_data" + os.sep
output_dir = cur_dir + os.sep + "output" + os.sep
key_dir = cur_dir + os.sep + "keys" + os.sep

SUPPORTED_KEY_TYPES = [
    "EC:prime256v1",
    "EC:brainpoolP256r1",
]

SUPPORTED_EC_KEY_TYPES = [
    "EC:prime256v1",
    "EC:brainpoolP256r1",
]

def run(cmd_str, ignore_result=0, exp_retcode=0):
    log.info("Running command:")
    log.info("%s" % (cmd_str,))
    pipes = subprocess.Popen(
        cmd_str,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    )
    std_out, std_err = pipes.communicate()
    std_out = std_out.strip()
    std_err = std_err.strip()
    log.info("%s" % std_out.decode())
    if not ignore_result:
        if pipes.returncode != exp_retcode:
            log.error("ERROR: Return code: %s, Expected return code: %s " % (pipes.returncode, exp_retcode))
            log.error("ERROR: std_err: %s" % std_err.decode())
        else:
            log.info("Command execution was successful.")
        assert pipes.returncode == exp_retcode

def parse_in_args():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_KEY_TYPES)),
        required=True)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in SUPPORTED_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    return args

def parse_in_ec_args():
    parser = argparse.ArgumentParser(
        description=__doc__, epilog=example_ec_text,
        formatter_class=argparse.RawTextHelpFormatter)
    required = parser.add_argument_group('required arguments')
    required.add_argument(
        '--key_type',
        default="",
        help='Supported key types => ``%s``' % ("``, ``".join(SUPPORTED_EC_KEY_TYPES)),
        required=True)

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    args = parser.parse_args()

    if args.key_type not in SUPPORTED_EC_KEY_TYPES:
        parser.print_help(sys.stderr)
        return None

    return args
