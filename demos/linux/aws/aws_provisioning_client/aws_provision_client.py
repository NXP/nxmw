# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

import os, logging, argparse

logging.basicConfig(level = logging.INFO)
parser = argparse.ArgumentParser(
            prog="openssl_provision.py",
            description="This script provisions the keys on the SA",
        )

parser.add_argument("-smcom", type=str, nargs=1, choices=['pcsc', 'vcom', 't1oi2c'], help="Specify the host device to connect through", required=True)
parser.add_argument("-port", type=str, nargs=1, help="Specify the port to connect to", required=True)
parser.add_argument("-keypath", type=str, nargs=1, help="Specify the path to the key", required=True)
args = parser.parse_args()

nxclitool = ".." + os.sep + ".." + os.sep + ".." + os.sep + ".." + os.sep + "binaries" + os.sep + "tmp" + os.sep + "nxclitool"

def nxclitool_connect(smcom, port, auth="symmetric", sctunn="ntag_aes128_ev2", key_id="0x00"):
    command = f"{nxclitool} connect -smcom {smcom} -port {port} -auth {auth} -sctunn {sctunn} -keyid {key_id}"
    logging.info(f"Running: {command}")
    os.system(command)

def nxclitool_disconnect():
    command = f"{nxclitool} disconnect"
    logging.info(f"Running: {command}")
    os.system(command)

def nxclitool_setkey(key_id, curve, in_path, operation):
    command = f"{nxclitool} setkey -keyid {key_id} -curve {curve} -in {in_path} -enable {operation}"
    logging.info(f"Running: {command}")
    os.system(command)

def main():
    path = args.keypath[0]
    path = os.path.abspath(path)
    curve = "prime256v1"
    port_name = args.port[0]
    if " " in port_name or "\t" in port_name:
        port_name = "\"" + port_name + "\""

    nxclitool_connect(smcom=args.smcom[0], port=port_name)
    nxclitool_setkey("0x02", curve, path, "sign")
    nxclitool_disconnect()

if __name__ == "__main__":
    main()