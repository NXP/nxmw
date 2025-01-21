# Copyright 2024 NXP
# SPDX-License-Identifier: BSD-3-Clause

import os, logging, argparse

logging.basicConfig(level = logging.INFO)
parser = argparse.ArgumentParser(
            prog="run_perso_nxclitool",
            description="This script runs personalization on the SA",
        )

# parser.add_argument("-toolpath", type=str, nargs=1, help="Specify the path of NX CLI tool binary", required=True)
parser.add_argument("-smcom", type=str, nargs=1, choices=['pcsc', 'vcom', 't1oi2c'], help="Specify the host device to connect through", required=True)
parser.add_argument("-port", type=str, nargs=1, help="Specify the port to connect to", required=True)
# parser.add_argument("-repoid", type=str, nargs=1, help="Specify the id for the repository", required=True)
parser.add_argument("-curve", type=str, nargs=1, choices=['prime256v1', 'brainpoolP256r1'], help="Specify the curve", required=True)
parser.add_argument("-certtype", type=str, nargs=1, choices=['pkcs7', 'x509'], help="Specify the certificate type (pkcs7 or x509)", required=True)
parser.add_argument("-certpath", type=str, nargs=1, help="Specify the path to certificate folder", required=True)
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

def certrepo_load_key(key_type, key_id, curve, cert_type, in_path):
    command = f"{nxclitool} certrepo-load-key -keytype {key_type} -keyid {key_id} -curve {curve} -certtype {cert_type} -in {in_path}"
    logging.info(f"Running: {command}")
    os.system(command)

def certrepo_create(repo_id, key_id, wcomm="full", rcomm="full", waccess="0x00", raccess="0x00", kcomm="na"):
    command = f"{nxclitool} certrepo-create -repoid {repo_id} -keyid {key_id} -wcomm {wcomm} -rcomm {rcomm} -waccess {waccess} -raccess {raccess} -kcomm {kcomm}"
    logging.info(f"Running: {command}")
    os.system(command)

def certrepo_load_cert(repo_id, cert_level, in_path, kcomm="na"):
    command = f"{nxclitool} certrepo-load-cert -repoid {repo_id} -certlevel {cert_level} -kcomm {kcomm} -in {in_path}"
    logging.info(f"Running: {command}")
    os.system(command)

def certrepo_load_mapping(repo_id, cert_level, in_path, kcomm="na"):
    command = f"{nxclitool} certrepo-load-mapping -repoid {repo_id} -certlevel {cert_level} -kcomm {kcomm} -in {in_path}"
    logging.info(f"Running: {command}")
    os.system(command)

def certrepo_activate(repo_id, kcomm="na"):
    command = f"{nxclitool} certrepo-activate -repoid {repo_id} -kcomm {kcomm}"
    logging.info(f"Running: {command}")
    os.system(command)

def nxclitool_setkey(key_id, curve, in_path, operation):
    command = f"{nxclitool} setkey -keyid {key_id} -curve {curve} -in {in_path} -enable {operation}"
    logging.info(f"Running: {command}")
    os.system(command)

def main():
    path = args.certpath[0]
    path = os.path.abspath(path)
    curve = args.curve[0]
    cert_type = args.certtype[0]
    repo_id = "0x01"
    port_name = args.port[0]
    if " " in port_name or "\t" in port_name:
        port_name = "\"" + port_name + "\""

    nxclitool_connect(smcom=args.smcom[0], port=port_name)
    certrepo_load_key("rootca", repo_id, curve, cert_type, path + os.sep + "host_root_certificate.der")
    certrepo_load_key("leaf", repo_id, curve, cert_type, path + os.sep + "device_leaf_keypair.der")
    certrepo_create(repo_id, repo_id)
    certrepo_load_cert(repo_id, "leaf", path + os.sep + "device_leaf_certificate.der")
    certrepo_load_cert(repo_id, "p1", path + os.sep + "device_p1_certificate.der")
    certrepo_load_cert(repo_id, "p2", path + os.sep + "device_p2_certificate.der")

    if cert_type == "pkcs7":
        certrepo_load_mapping(repo_id, "leaf", path + os.sep + "host_leaf_cert_mapping.bin")
        certrepo_load_mapping(repo_id, "p1", path + os.sep + "host_p1_cert_mapping.bin")
        certrepo_load_mapping(repo_id, "p2", path + os.sep + "host_p2_cert_mapping.bin")

    certrepo_activate(repo_id)
    nxclitool_disconnect()

if __name__ == "__main__":
    main()