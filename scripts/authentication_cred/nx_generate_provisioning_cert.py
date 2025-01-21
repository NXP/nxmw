# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
#

"""
This script generates fresh certificates upto 3 level depth for host and device,
of PKCS7 and X509 type, and rev1 and rev3 along with respective root certificates.
The certificates are placed in out_folder under the path supplied.
"""

import os, sys, logging

class LoggingColorFormat(logging.Formatter):
    green = "\x1b[32;20m"
    reset = "\x1b[0m"
    format = "%(levelname)s: %(message)s"

    FORMATS = {
        logging.INFO: green + format + reset
    }

    def format(self, message):
        logging_format = self.FORMATS.get(message.levelno)
        formatter = logging.Formatter(logging_format)
        return formatter.format(message)

# logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(LoggingColorFormat())
logger.addHandler(console)

# Argument list:
# 1. Specify the path to store the certificate

depth_list = ["depth1", "depth2", "depth3"]
cert_type_list = ['pkcs7', 'x509']
curve_list = ['nist_p', 'brainpool']
rev_list = ["rev1", "rev3"]
ext_folder = "ext"

level_dict = dict()
level_dict["depth1"] = ["leaf"]
level_dict["depth2"] = ["p1", "leaf"]
level_dict["depth3"] = ["p2", "p1", "leaf"]

cipher = dict()
cipher['nist_p'] = "prime256v1"
cipher['brainpool'] = "brainpoolP256r1"

subject_dict = dict()
subject_dict["p2"] = "/C=NL/ST=Eindhoven/L=Eindhoven/O=NXP/CN=NXP P2 IntermCAvE201"
subject_dict["p1"] = "/C=NL/ST=Eindhoven/L=Eindhoven/O=NXP/CN=NXP P1 IntermCAvE201"
subject_dict["leaf"] = "/C=NL/ST=Eindhoven/L=Eindhoven/O=NXP/CN=NXP LEAF CERTIFICATE"

def copy_mapping_to_cert_folder(cert_path, level):
    mapping = b'\xa0\x0e0\x81\xa0\x810\x81\x02\x821\x820\x82\xa0\x83'
    map_name = f"host_{level}_cert_mapping.bin"
    logger.info(f"Creating mapping file: {map_name}")
    map_name = f"{cert_path}{os.sep}{map_name}"
    with open(map_name, "wb") as map_fh:
        map_fh.write(mapping)

def generate_root_cert(openssl, depth, cert_type, rev, curve, path, device):
    subject = "/C=NL/ST=Eindhoven/L=Eindhoven/O=NXP/CN=NXP Auth RootCAvE201"
    folder = os.path.join(path, "out_folder", f"cert_{depth}_{cert_type}_{rev}", "cert_and_key", curve)
    folder = os.path.abspath(folder)
    if not os.path.exists(folder):
        os.makedirs(folder)
        logger.info(f"Created path: {folder}")
    else: logger.info(f"Using the already available path: {folder}")

    ext_file = ext_folder + os.sep + "x509.ext"

    cert_out = os.path.join(folder, f"{device}_root_certificate.der")
    out_dir = os.path.join(path, "out_folder")
    curve = "prime256v1" if curve == "nist_p" else "brainpoolP256r1"

    command = f"{openssl} ecparam -name {curve} -genkey -noout -out {out_dir}{os.sep}{device}_root_keypair.pem"
    logger.info(f"Running: {command}")
    os.system(command)

    command = f"{openssl} req -new -sha256 -key {out_dir}{os.sep}{device}_root_keypair.pem -out {out_dir}{os.sep}{device}_root_certificate.csr -subj \"{subject}\""
    logger.info(f"Running: {command}")
    os.system(command)

    command = f"{openssl} x509 -extfile {ext_file} -extensions ca -signkey {out_dir}{os.sep}{device}_root_keypair.pem -in {out_dir}{os.sep}{device}_root_certificate.csr -req -days 3650 -out {out_dir}{os.sep}{device}_root_certificate.pem"
    logger.info(f"Running: {command}")
    os.system(command)

    command = f"{openssl} ec -in {out_dir}{os.sep}{device}_root_keypair.pem -outform DER -out {out_dir}{os.sep}{device}_root_keypair.der"
    logger.info(f"Running: {command}")
    os.system(command)

    if cert_type == "pkcs7":
        command = f"openssl crl2pkcs7 -nocrl -certfile {out_dir}{os.sep}{device}_root_certificate.pem -outform DER -out {cert_out}"
        logger.info(f"Running: {command}")
        os.system(command)
    else:
        command = f"{openssl} x509 -in {out_dir}{os.sep}{device}_root_certificate.pem -outform DER -out {cert_out}"
        logger.info(f"Running: {command}")
        os.system(command)

    return folder, out_dir

def generate_level_certs(openssl, depth, cert_type, rev, curve, cert_path, device, out_dir):
    curve = "prime256v1" if curve == "nist_p" else "brainpoolP256r1"
    parent_cert = f"{device}_root_certificate.pem"
    parent_kp = f"{device}_root_keypair.pem"
    current_cert = ""
    ext_file = f"-extfile {ext_folder}{os.sep}x509.ext -extensions ca"

    for level in level_dict[depth]:
        if level == "leaf":
            if rev == "rev3": ext_file = f"-extfile {ext_folder}{os.sep}no_ca_x509.ext -extensions ca"
            else: ext_file = ""
        current_cert = f"{device}_{level}_certificate"

        command = f"{openssl} ecparam -name {curve} -genkey -noout -out {out_dir}{os.sep}{device}_{level}_keypair.pem"
        logger.info(f"Running: {command}")
        os.system(command)

        command = f"{openssl} req -new -sha256 -key {out_dir}{os.sep}{device}_{level}_keypair.pem -out {out_dir}{os.sep}{current_cert}.csr -subj \"{subject_dict[level]}\""
        logger.info(f"Running: {command}")
        os.system(command)

        if cert_type == "x509" and level == "leaf":
            command = f"{openssl} x509 -req -in {out_dir}{os.sep}{current_cert}.csr -CA {out_dir}{os.sep}{parent_cert} -CAkey {out_dir}{os.sep}{parent_kp} -CAcreateserial -out {out_dir}{os.sep}{current_cert}.pem -days 3650 -sha256"
        else:
            command = f"{openssl} x509 {ext_file} -req -in {out_dir}{os.sep}{current_cert}.csr -CA {out_dir}{os.sep}{parent_cert} -CAkey {out_dir}{os.sep}{parent_kp} -CAcreateserial -out {out_dir}{os.sep}{current_cert}.pem -days 3650 -sha256"
        logger.info(f"Running: {command}")
        os.system(command)

        command = f"{openssl} ec -in {out_dir}{os.sep}{device}_{level}_keypair.pem -outform DER -out {out_dir}{os.sep}{device}_{level}_keypair.der"
        if level == "leaf": command = f"{openssl} ec -in {out_dir}{os.sep}{device}_{level}_keypair.pem -outform DER -out {cert_path}{os.sep}{device}_{level}_keypair.der"
        logger.info(f"Running: {command}")
        os.system(command)

        if cert_type == "pkcs7":
            command = f"{openssl} crl2pkcs7 -nocrl -certfile {out_dir}{os.sep}{current_cert}.pem -outform DER -out {cert_path}{os.sep}{current_cert}.der"
            logger.info(f"Running: {command}")
            os.system(command)
            copy_mapping_to_cert_folder(cert_path, level)
        else:
            command = f"{openssl} x509 -in {out_dir}{os.sep}{current_cert}.pem -outform DER -out {cert_path}{os.sep}{current_cert}.der"
            logger.info(f"Running: {command}")
            os.system(command)

        parent_cert = f"{current_cert}.pem"
        parent_kp = f"{device}_{level}_keypair.pem"

def cleanup(out_dir):
    files_to_rem = os.listdir(out_dir)
    files_to_rem = [file for file in files_to_rem if os.path.isfile(os.path.join(out_dir, file))]
    for file in files_to_rem:
        #logger.info(f"Removing the unnecessary file: {file}")
        os.remove(os.path.join(out_dir, file))

def main():
    if len(sys.argv) < 2:
        print("Supply the path where certificate folder is to be created. Example invocation:")
        print("\tpython generate_provisioning_cert.py <OUTPUT_PATH>")
        print("\tpython generate_provisioning_cert.py .")
        exit()
    else: path = sys.argv[1]
    openssl = "openssl"

    for device in ["host", "device"]:
        for cert_type in cert_type_list:
            for rev in rev_list:
                for depth in depth_list:
                    for curve in curve_list:
                        cert_path, out_dir = generate_root_cert(openssl, depth, cert_type, rev, curve, path, device)
                        generate_level_certs(openssl, depth, cert_type, rev, curve, cert_path, device, out_dir)

    cleanup(out_dir)

if __name__ == "__main__":
    main()