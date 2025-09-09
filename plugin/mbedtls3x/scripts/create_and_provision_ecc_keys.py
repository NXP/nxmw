#
# Copyright 2025 NXP
# SPDX-License-Identifier: BSD-3-Clause
#

"""

This example showcases provision keys on IC using nxcli tool.

"""
import argparse
import logging
import os
import sys
from utils import *
log = logging.getLogger(__name__)

#KeyID
CLIENT_KEY_PAIR_ID = 0x00000002

example_text = '''
Example invocation:
    python create_and_provision_ecc_keys.py -auth_type symmetric -smcom vcom -port COM7 -curve prime256v1 -waccess 0xE
    python create_and_provision_ecc_keys.py -auth_type symmetric -smcom vcom -port COM7 -curve brainpoolP256r1 -waccess 0xE
    python create_and_provision_ecc_keys.py -auth_type sigma_i_verifier -auth_curve prime256v1 -repoid 0x01 -smcom vcom -port COM7 -curve prime256v1 -waccess 0xE
    python create_and_provision_ecc_keys.py -auth_type sigma_i_verifier -auth_curve prime256v1 -repoid 0x01 -smcom vcom -port COM7 -curve brainpoolP256r1 -waccess 0xE
'''

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

    optional.add_argument(
        '-waccess',
        default="0x0E",
        help='waccess parameter (e.g., "0x00", "0x0F"). Default: "0x0E".'
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

def nxclitool_setkey(nxclitool, key_id, curve, in_path, operation, accessrights):
    command = f"{nxclitool} setkey -keyid {key_id} -curve {curve} -in {in_path} -enable {operation} -waccess {accessrights}"
    log.info(f"Running: {command}")
    os.system(command)

def nxclitool_getrefkey(nxclitool, key_id, in_path, out_path):
    command = f"{nxclitool} get-ref-key -keyid {key_id} -in {in_path} -out {out_path}"
    log.info(f"Running: {command}")
    os.system(command)


def main():
    #edit the keyid
    keyID = CLIENT_KEY_PAIR_ID
    args = parse_args()
    cur_dir = os.path.abspath(os.path.dirname(__file__))
    nxclitool = os.path.join("..", "..", "..", "binaries", "tmp", "nxclitool")
    auth_type = args.auth_type
    auth_curve = args.auth_curve
    repoid = args.repoid
    curve = args.curve
    port_name = args.port
    if " " in port_name or "\t" in port_name:
        port_name = f"\"{port_name}\""

    keys_dir = os.path.join(cur_dir, '..', 'keys', curve)
    # Create the directory structure if it doesn't exist
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)

    KEY_TYPE_FILE_NAME = curve + '.pem'
    KEY_TYPE_FILE = os.path.join(cur_dir, '..', 'keys', curve, KEY_TYPE_FILE_NAME)

    ROOT_CA_CER = os.path.join(cur_dir, '..', 'keys', curve, 'tls_rootca.cer')
    ROOT_CA_SRL = os.path.join(cur_dir, '..', 'keys', curve, 'tls_rootca.srl')
    ROOT_CA_KEY_PEM = os.path.join(cur_dir, '..', 'keys', curve, 'tls_rootca_key.pem')
    ROOT_CA_KEY_PUBLIC_PEM = os.path.join(cur_dir, '..', 'keys', curve, 'tls_rootca_pub_key.pem')
    ROOT_CA_KEY_DER = os.path.join(cur_dir, '..', 'keys', curve, 'tls_rootca_key.der')

    CLIENT_KEY_PEM = os.path.join(cur_dir, '..', 'keys', curve, 'tls_client_key.pem')
    CLIENT_KEY_REF_PEM = os.path.join(cur_dir, '..', 'keys', curve, 'tls_client_key_ref.pem')
    CLIENT_KEY_PUBLIC_PEM = os.path.join(cur_dir, '..', 'keys', curve, 'tls_client_key_pub.pem')
    CLIENT_CER = os.path.join(cur_dir, '..', 'keys', curve, 'tls_client.cer')

    SERVER_KEY_PEM = os.path.join(cur_dir, '..', 'keys', curve, 'tls_server_key.pem')
    SERVER_CSR = os.path.join(cur_dir, '..', 'keys', curve, 'tls_server.csr')
    SERVER_CERTIFICATE = os.path.join(cur_dir, '..', 'keys', curve, 'tls_server.cer')

    openssl_config_file = os.path.join(cur_dir, '..', '..', '..', 'ext', 'openssl', 'ssl', 'openssl.cnf')
    if sys.platform.startswith("win"):
        openssl = os.path.join(cur_dir, '..', '..', '..', 'ext', 'openssl', 'bin', 'openssl.exe')
        os.environ['OPENSSL_CONF'] = openssl_config_file
    else:
        openssl = 'openssl'

    SUBJECT = "/C=AB/ST=XY/L=LH/O=NXP-Demo-CA/OU=Demo-Unit/CN=localhost"

    cmd_str = "\"%s\" ecparam -name \"%s\" -out \"%s\"" % (openssl, curve, KEY_TYPE_FILE)
    run(cmd_str)

    cmd_str = "\"%s\" ecparam -in \"%s\" -genkey -noout -out \"%s\"" % (openssl, KEY_TYPE_FILE, ROOT_CA_KEY_PEM)
    run(cmd_str)

    cmd_str = "\"%s\" ec -in \"%s\" -outform DER -out \"%s\"" % (openssl, ROOT_CA_KEY_PEM, ROOT_CA_KEY_DER)
    run(cmd_str)

    cmd_str = "\"%s\" ec -in \"%s\" -pubout -out \"%s\"" % (openssl, ROOT_CA_KEY_PEM, ROOT_CA_KEY_PUBLIC_PEM)
    run(cmd_str)

    #create CA certificates
    cmd_str = "\"%s\" req -x509 -new -nodes -key \"%s\" -subj \"%s\" -days 2800 -out \"%s\" -config \"%s\"" % (openssl, ROOT_CA_KEY_PEM, SUBJECT, ROOT_CA_CER, openssl_config_file)
    run(cmd_str)

    #Create client key and extract public part
    cmd_str = "\"%s\" ecparam -in \"%s\" -genkey -out \"%s\"" % (openssl, KEY_TYPE_FILE, CLIENT_KEY_PEM)
    run(cmd_str)

    cmd_str = "\"%s\" ec -in \"%s\" -pubout -out \"%s\"" % (openssl, CLIENT_KEY_PEM, CLIENT_KEY_PUBLIC_PEM)
    run(cmd_str)

    #Now create CSR
    cmd_str = "\"%s\" req -new -key \"%s\" -subj \"%s\" -out \"%s\" -config \"%s\"" % (openssl, CLIENT_KEY_PEM, SUBJECT, CLIENT_CER, openssl_config_file)
    run(cmd_str)

    #Create CA signed client certificate
    if os.path.isfile(ROOT_CA_SRL) == True:
        cmd_str = "\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" -CAserial \"%s\" -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, CLIENT_CER, ROOT_CA_SRL, ROOT_CA_CER, ROOT_CA_KEY_PEM, CLIENT_CER)
    else:
        cmd_str = "\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" -CAserial \"%s\" -CAcreateserial -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, CLIENT_CER, ROOT_CA_SRL, ROOT_CA_CER, ROOT_CA_KEY_PEM, CLIENT_CER)
    run(cmd_str)

    #Create server key
    cmd_str = "\"%s\" ecparam -in \"%s\" -genkey -out \"%s\"" % (openssl, KEY_TYPE_FILE, SERVER_KEY_PEM)
    run(cmd_str)

    #Create CSR a new
    cmd_str = "\"%s\" req -new -key \"%s\" -subj \"%s\" -out \"%s\" -config \"%s\"" % (openssl, SERVER_KEY_PEM, SUBJECT, SERVER_CSR, openssl_config_file)
    run(cmd_str)

    #Create a CA signed server certificate
    if os.path.isfile(ROOT_CA_SRL) == True:
        cmd_str = "\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" -CAserial \"%s\" -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, SERVER_CSR, ROOT_CA_SRL, ROOT_CA_CER, ROOT_CA_KEY_PEM, SERVER_CERTIFICATE)
    else:
        cmd_str = "\"%s\" x509 -req -sha256 -days 2800 -in \"%s\" -CAserial \"%s\" -CAcreateserial -CA \"%s\" -CAkey \"%s\" -out \"%s\" " % (openssl, SERVER_CSR, ROOT_CA_SRL, ROOT_CA_CER, ROOT_CA_KEY_PEM, SERVER_CERTIFICATE)
    run(cmd_str)

    nxclitool_connect(nxclitool, smcom=args.smcom, port=port_name, auth=auth_type, curve=auth_curve, repo_id=repoid)
    nxclitool_setkey(nxclitool,  hex(keyID), curve, CLIENT_KEY_PEM, "sign", accessrights=args.waccess)
    nxclitool_getrefkey(nxclitool, hex(keyID), CLIENT_KEY_PUBLIC_PEM, CLIENT_KEY_REF_PEM)
    nxclitool_disconnect(nxclitool)

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()