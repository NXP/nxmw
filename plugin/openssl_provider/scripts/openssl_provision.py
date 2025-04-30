#
# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""

This example showcases provision keys on IC using nxcli tool.

"""
import argparse
import logging
import os
import sys
from openssl_util import *
log = logging.getLogger(__name__)

example_text = '''
Example invocation:
    python %s -smcom {vcom, pcsc, t1oi2c} -port {COM7|"NXP Semiconductors P71 T=0, T=1 Driver 0"} -curve {prime256v1|brainpoolP256r1} -keypath ../keys/prime256v1/ecc_key_kp.pem
    python %s -smcom {vcom, pcsc, t1oi2c} -port {COM7|"NXP Semiconductors P71 T=0, T=1 Driver 0"} -curve {prime256v1|brainpoolP256r1} -keypath ../keys/brainpoolP256r1/ecc_key_kp.pem
''' % (__file__, __file__)

def parse_args():

    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=example_text,
        formatter_class=argparse.RawTextHelpFormatter
    )

    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    required.add_argument(
        '-smcom',
        default="t1oi2c",
        help='Specify the host device to connect through (e.g., "pcsc", "vcom"). Default: "t1oi2c".'
    )
    required.add_argument(
        '-port',
        default="none",
        help='Parameter to connect NX IC (e.g., "COM3", "NXP Semiconductors P71 T=0, T=1 Driver 0" , "/dev/ttyACM0"). Default: "none".'
    )
    required.add_argument(
        '-curve',
        default="prime256v1",
        help='Curve parameter (e.g., "prime256v1", "brainpoolP256r1"). Default: "prime256v1".'
    )

    required.add_argument(
        '-keypath',
        required=True,
        help='Path to the key file (e.g., "../keys/brainpoolP256r1", "../keys/prime256v1").'
    )

    required.add_argument(
        '-auth_type',
        default="symmetric",
        help='auth_type parameter (e.g., "symmetric", "sigma_i_verifier", "sigma_i_prover"). Default: "symmetric".'
    )

    optional.add_argument(
        '-auth_curve',
        default="prime256v1",
        help='Curve parameter (e.g., "prime256v1", "brainpoolP256r1"). Default: "prime256v1".'
    )

    optional.add_argument(
        '-repoid',
        default="0x01",
        help='RepoID parameter (e.g., "0x00", "0x07"). Default: "0x01".'
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    return args

def nxclitool_connect(nxclitool, smcom, port, auth, curve, repo_id, sctunn="ntag_aes128_ev2", key_id="0x00"):
    if auth == "symmetric":
        command = f"{nxclitool} connect -smcom {smcom} -port {port} -auth {auth} -sctunn {sctunn} -keyid {key_id}"
    else:
        command = f"{nxclitool} connect -smcom {smcom} -port {port} -auth {auth} -sctunn {sctunn} -curve {curve} -repoid {repo_id}"
    log.info(f"Running: {command}")
    os.system(command)

def nxclitool_disconnect(nxclitool):
    command = f"{nxclitool} disconnect"
    log.info(f"Running: {command}")
    os.system(command)

def nxclitool_setkey(nxclitool, key_id, curve, in_path, operation):
    command = f"{nxclitool} setkey -keyid {key_id} -curve {curve} -in {in_path} -enable {operation} -waccess 0x0E"
    log.info(f"Running: {command}")
    os.system(command)


def main():
    args = parse_args()
    nxclitool = os.path.join("..", "..", "..", "binaries", "tmp", "nxclitool")
    key_path = os.path.abspath(args.keypath)
    auth_type = args.auth_type
    auth_curve = args.auth_curve
    repoid = args.repoid
    curve = args.curve
    port_name = args.port
    if " " in port_name or "\t" in port_name:
        port_name = f"\"{port_name}\""
    nxclitool_connect(nxclitool, smcom=args.smcom, port=port_name, auth=auth_type, curve=auth_curve, repo_id=repoid)
    nxclitool_setkey(nxclitool, "0x02", curve, key_path, "sign")
    nxclitool_setkey(nxclitool, "0x04", curve, key_path, "ecdh")
    nxclitool_disconnect(nxclitool)


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()