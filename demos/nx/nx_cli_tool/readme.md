# NX-CLI Tool

This tool is a command line utility to evaluate the secure authenticator on Windows / Linux environment.

## Build

- Build NX middleware stack on Linux. Refer [**Linux build**](../../../doc/linux/readme.md).

- Build NX middleware stack for Windows. Refer [**Windows build**](../../../doc/windows/readme.md).

  - Select CMake options:
    - `NXMW_All_Auth_Code=Enabled`

  - Project:`nxclitool`


## About the Tool

This tool is a command line utility to evaluate the secure authenticator
on Windows / Linux environment. The tool can be used to perform various
cryptographic operations / personalization of SA.

It supports following commands:

| Command        | Description                                                             |
| ---------------| ------------------------------------------------------------------------|
| connect        | Connect to SA                                                           |
| disconnect     | Disconnect from SA                                                      |
| get-uid        | Get UID from SA                                                         |
| genkey         | Generates ECC Key in SA and stores the public key to a file             |
| get-ref-key    | Generates a reference key                                               |
| rand           | Generate random numbers from SA                                         |
| setkey         | Set a private key inside SA                                             |
| certrepo-*     | Certificate repository commands                                         |
| create-bin     | Creates a standard data file inside SA                                  |
| setbin         | Set data to a standard data file inside SA                              |
| getbin         | Get data from standard data file in SA                                  |
| list-fileid    | Fetches the list of file IDs inside SA                                  |
| list-eckey     | Fetches the list and properties of EC keys inside SA                    |
| set-i2c_mgnt   | Set I2C configuration                                                   |
| set-cert_mgnt  | Set certificate configuration                                           |
| dgst-sha256    | Generate SHA-256 message digest from SA                                 |
| dgst-sign      | Sign the message digest using SA                                        |
| dgst-verify    | Verify the signature using SA                                           |
| derive-ecdh    | Derive an ECDH key from SA                                              |

Refer individual command sections for more details.

Ensure that connect command is called before performing any crypto operations.

## Connect/Disconnect Command

Connect command creates a temporary file with data related to connection
context. (The actual connection to SA is done only in next crypto
operation call. And after every crypto operation call, session is
closed.) The disconnect command will delete the temporary file created
during connect call.

**Command Format:**
```
nxclitool connect [OPTIONS] nxclitool disconnect
```

**Options:**

Common options required for all auth types:

- **-smcom**: Host device to connect to. Accepted values:
    - `pcsc`: To connect to the simulator via pcsc
    - `vcom`: To connect to the SA via vcom
    - `t1oi2c`: To connect to the SA via T=1oI2C

-  **-port**: Port of the host device. Set the value to \"default\" to
    use the default port. If skipped, default port will be used

-   **-auth**: Authentication type. Accepted values:
    - `none`
    - `sigma_i_verifier`
    - `sigma_i_prover`
    - `symmetric`

-   **-sctunn**: Secure tunneling type. Accepted values:
    - `none`
    - `ntag_aes128_aes256_ev2`
    - `ccm_aes256`
    - `ntag_aes128_ev2`
    - `ntag_aes256_ev2`

Options required for symmetric auth types:

- **-keyid**: Key ID for symmetric auth. Accepted values: 0x00 - 0x04

Options required for sigma auth types:

- **-curve**: ECC Curve type for sigma auth type. Accepted values:
    - `brainpoolP256r1`
    - `prime256v1`
    - `na`

- **-repoid**: Repository ID in hex format for sigma auth type

**Example**

Command to connect with symmetric auth type:

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00

<... Any Crypto Operation ...>

nxclitool disconnect
```

For sigma auth type:

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth sigma_i_verifier -sctunn ntag_aes128_ev2 -repoid 0x01 -curve prime256v1

<... Any Crypto Operation ...>

nxclitool disconnect
```


## Get UID Command

Get UID from Secure Authenticator. This command does not require any options.

**Command Format**

```
nxclitool get-uid [OPTIONS]
```

**Options**

-   **-out**: Store the uid to a file (optional argument)

**Example**
```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool get-uid -out uid.txt
./nxclitool disconnect
```


## List EC Key Command

Fetches the list and properties of EC keys inside Secure Authenticator. This command does not require any options.

**Command Format**

```
nxclitool list-eckey
```

**Example**
```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool list-eckey
./nxclitool disconnect
```


## Random Generation Command

Generates specified number of random bytes from SA.

**Command Format**

```
nxclitool rand -bytes [NO_OF_BYTES]
```

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool rand -bytes 20
./nxclitool disconnect
```


## Generate EC Key Command

Generates ECC key (curve type as input parameter). If an optional file
path is provided, the public key will be stored in PEM format.

**Command Format**
```
nxclitool genkey [OPTIONS]
```

**Options**

-   **-keyid**: Key ID for asymmetric keypair generation should be in HEX format.
    Range: **0x00 to 0x04**

-   **-curve**: Curve type for keypair generation. Accepted values:
    - `brainpoolP256r1`: ECC curve type BRAINPOOL_256
    - `prime256v1`: ECC curve type NIST_P256

-   **-enable**: Operation to be performed by the key. Accepted values:
    -   `none`
    -   `ecdh`
    -   `sign`
    -   `sigmai`
    -   `sdm`

-   **-waccess**: Write and Read Access Rights respectively,
    required to write to/read from the repository. Accepted values:
    -   `0x00 to 0x0C` Auth required
    -   `0x0D` Free over I2C
    -   `0x0E` Free Access
    -   `0x0F` No Access

-   **-out**: Store the public key to a file in PEM format (optional argument).

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool genkey -keyid 0x02 -curve brainpoolP256r1 -out pub.key
./nxclitool disconnect
```


## Set Key Command

Set a private key inside SA (Key ID and key file in PEM format as input
parameter).

**Command Format**
```
nxclitool setkey [OPTIONS]
```

**Options**

-   **-curve**: Curve type for keypair generation. Accepted values
    - `brainpoolP256r1`: ECC curve type BRAINPOOL_256
    - `prime256v1`: ECC curve type NIST_P256

-   **-enable**: Operation to be performed by the key. Accepted values:
    -   `none`
    -   `ecdh`
    -   `sign`

-   **-in**: Path to the input certificate/key in PEM format

-   **-keyid**: Key ID for asymmetric keypair generation should be in HEX
    format. Range: **0x00 to 0x04**

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool setkey -keyid 0x02 -curve prime256v1 -in key.pem -enable sign
./nxclitool disconnect
```

## Get Reference Key Command

Generates a reference key using key ID (where the private key is stored
in SA) and the public key in PEM format (Key ID and public key file in
PEM format as input parameter).

Note: As there is no communication involved with SA for this command,
there is no need to use the connect/disconnect command.

**Command Format**
```
nxclitool get-ref-key [OPTIONS]
```

**Options**

-   **-in**: Path to the public key in PEM format
-   **-keyid**: Key ID for asymmetric keypair generation should be in HEX
    format. Range: **0x00 to 0x04**
-   **-out**: Store the public key to a file in PEM format (optional
    argument)

**Example**
```
nxclitool get-ref-key -keyid 0x02 -in pub.key -out ref.key
```


## Create Certificate Repository Command

Creates a certificate repository in the SA.

**Command Format**
```
nxclitool certrepo-create [OPTIONS]
```

**Options**

-   **-keyid**: ECC private key ID associated with the repository

-   **-repoid**: Certificate Repository ID

-   **-wcomm, -rcomm, -kcomm**: Write, Read, Known communication modes
    respectively, required to write to/read from the repository.
    Accepted values:
    -   `full`
    -   `mac`
    -   `na`
    -   `plain`

-   **-waccess, -raccess**: Write and Read Access Rights respectively,
    required to write to/read from the repository. Accepted values:
    -   `0x00 to 0x0C` Auth required
    -   `0x0D` Free over I2C
    -   `0x0E` Free Access
    -   `0x0F` No Access

**Example**
```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool certrepo-create -repoid 0x01 -keyid 0x01 -wcomm full -rcomm full -waccess 0x0 -raccess 0x0 -kcomm na
./nxclitool disconnect
```


## Activate Certificate Repository Command

Activates the certificate repository.

**Command Format**
```
nxclitool certrepo-activate [OPTIONS]
```

**Options**

- **-kcomm**: Known Communication Mode, required to write to/read from the repository. Accepted values:
    - `full`
    - `mac`
    - `na`
    - `plain`

- **-repoid**: Certificate Repository ID

**Example**
```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool certrepo-activate -repoid 0x01 -kcomm na
./nxclitool disconnect
```

## Reset Certificate Repository Command

Resets the certificates/keys loaded in the certificate repository.

**Command Format**
```
nxclitool certrepo-reset [OPTIONS]
```

**Options**:

-   **-repoid**: Certificate Repository ID. Default: 0x03
-   **-waccess, -raccess**: Write, Read Access Rights respectively,
    required to write to/read from the repository. Accepted values:
    -   `0x00 to 0x0C` Auth required
    -   `0x0D` Free over I2C
    -   `0x0E` Free Access
    -   `0x0F` No Access
-   **-wcomm, -rcomm, -kcomm**: Write, Read, Known communication modes
    respectively, required to write to/read from the repository.
    Accepted values:
    -   `full`
    -   `mac`
    -   `na`
    -   `plain`

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool certrepo-reset -repoid 0x01 -wcomm full -rcomm full -waccess 0x0 -raccess 0x0 -kcomm na
./nxclitool disconnect
```

## Manage Certificate Repository commands

**certrepo-load-key / certrepo-load-cert / certrepo-load-mapping**
commands can be used to manage a certificate repository in the SA.

**Command Format**
```
./nxclitool certrepo-load-key [OPTIONS]
./nxclitool certrepo-load-cert [OPTIONS]
./nxclitool certrepo-load-mapping [OPTIONS]
```

**Options**

-   **-certlevel**: Level of the certificate. Required with
    **certrepo-load-cert**and **certrepo-load-mapping**. Accepted values:
    -   `leaf`
    -   `p1`
    -   `p2`
    -   `root`

-   **-kcomm** : Known Communication Mode, required to write to/read from
    the repository. Required with **certrepo-load-cert**and
    **certrepo-load-mapping**. Accepted values:
    -   `full`
    -   `mac`
    -   `na`
    -   `plain`

-   **-repoid**: Certificate Repository ID in hex format. Required with
    **certrepo-load-cert** and **certrepo-load-mapping**

-   **-curve**: ECC Curve type for the key. Required with
    **certrepo-load-key**. Accepted values:
    -   `brainpoolP256r1`
    -   `prime256v1`
    -   `na`

-   **-in**: Path to the input certificate/key. Required with
    **certrepo-load-cert**, **certrepo-load-mapping** and
    **certrepo-load-key**

-   **-keyid**: Key ID for setting Root CA Key. Required with
    **certrepo-load-key**

-   **-certtype**: Certificate wrapping. Required with
    **certrepo-load-key**. Accepted values:
    -   `pkcs7`
    -   `x509`

-   **-waccess, -raccess**: Write, Read Access Rights respectively,
    required to write to/read from the repository. Required with
    **certrepo-load-key**. Accepted values:
    -   `0x00 to 0x0C` Auth required
    -   `0x0D` Free over I2C
    -   `0x0E` Free Access
    -   `0x0F` No Access

-   **-keytype**: Type of key to be loaded in the repository. Required
    with **certrepo-load-key**. Accepted values:
    -   `leaf`: Device Leaf Key
    -   `rootca`: Root CA Key

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool certrepo-load-key -keytype rootca -keyid 0x00 -curve prime256v1 -certtype pkcs7 -in host_root_certificate.der
./nxclitool disconnect
```

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn
./ntag_aes128_ev2 -keyid 0x00 nxclitool certrepo-load-cert -repoid 0x01 -certlevel leaf -kcomm na -in device_leaf_certificate.der
./nxclitool disconnect
```

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn
./ntag_aes128_ev2 -keyid 0x00 nxclitool certrepo-load-mapping -repoid 0x01 -certlevel leaf -kcomm na -in device_leaf_certificate.der
./nxclitool disconnect
```


## Read Certificate Repository

Reads a certificate from the repository using **certrepo-read-cert** or
the repository metadata using **certrepo-read-metadata**.

**Command Format**
```
nxclitool certrepo-read-cert [OPTIONS]
nxclitool certrepo-read-metadata [OPTIONS]
```

**Options**

-   **-out**: File path where the certificate will be stored. Required
    with **certrepo-read-cert**

-   **-kcomm** : Known Communication Mode for the repository. Required
    with **certrepo-read-cert**. Accepted values:
    -   `full`
    -   `mac`
    -   `na`
    -   `plain`

-   **-repoid**: Certificate Repository ID. Required with both commands

-   **-certlevel**: Level of the certificate. Required with
    **certrepo-read-cert**. Accepted values:
    -   `leaf`
    -   `p1`
    -   `p2`
    -   `root`

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool certrepo-read-cert -repoid 0x01 -certlevel p2 -kcomm na -out cert.der
./nxclitool disconnect
```

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool certrepo-read-metadata -repoid 0x01
./nxclitool disconnect
```

## Create Binary File Command

Creates a standard data file inside SA of the specified length. Length in bytes
should not be more than 1024.

**Command Format**
```
nxclitool create-bin [OPTIONS]
```

**Options**

-   **-bytes**: File size in bytes
-   **-caccess, -raccess, -rwaccess, -waccess**: Change, Read, Read-Write, Write Access Rights respectively. Accepted values:
    -   `0x00 to 0x0C`: Auth required
    -   `0x0D`: Free over I2C
    -   `0x0E`: Free Access
    -   `0x0F`: No Access
-   **-fcomm**: File communication mode. Accepted values:
    - `full`
    - `mac`
    - `na`
    - `plain`
-   **-id**: File ID in hex format

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool create-bin -id 0x04 -bytes 100 -raccess 0x0F -waccess 0x0F -rwaccess 0x0F -caccess 0x0F -fcomm full
./nxclitool disconnect
```


## List File IDs Command

Fetches the list of standard data file IDs inside SA.

**Command Format**
```
nxclitool list-fileid
```

Note: **list-fileid** command does not require any additional arguments.


**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool list-fileid
./nxclitool disconnect
```

## Set Binary Command

Sets data from a file to a standard data file inside SA.

**Command Format**
```
nxclitool setbin [OPTIONS]
```

**Options**

-   **\[-bytes\]**: No. of bytes to store (optional). Default: No. of bytes from offset to EOF
-   **-id**: File ID in hex format
-   **-in**: Path to the file to read
-   **\[-offset\]**: Offset of data to read from and store at in SA (optional). Default: 0


**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool setbin -id 0x04 -bytes 12 -offset 10 -in data_in.txt
./nxclitool disconnect
```

>**Note:** 
If **-offset** option is not specified, default value used is 0 (zero).


>**Note:** 
If **-offset** option is specified, CLI tool will read data from input file from the start
    and store it in standard data file inside SA at the offset value specified.


>**Note:** 
If **-bytes** option is not specified, default value used is the size of file in bytes.


## Get Binary Command

Gets data from a standard data file inside SA and stores it in a file in file system.

**Command Format**
```
nxclitool getbin [OPTIONS]
```

**Options**

-   **\[-bytes\]**: No. of bytes to store (optional). Default: No. of bytes from offset to EOF
-   **-id**: File ID in hex format
-   **\[-offset\]**: Offset of data to read from SA standard file (optional). Default: 0
-   **\[-out\]**: Stores the fetched data to a file on this path (optional)


**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool getbin -id 0x04 -bytes 12 -offset 10 -out data_out.txt
./nxclitool disconnect
```

>**Note:** 
If **-offset** option is not specified, default value used is 0 (zero).


>**Note:** 
If **-offset** option is specified, CLI tool will read data from standard data file
    in the SA from the offset specified and store it in the output file.


>**Note:** 
If **-bytes** option is not specified, default value used is the number of bytes from
    offset value to EOF of standard data file



## Personalization of SA Using NX CLI Tool

- Connect to the SA.

```
nxclitool connect -smcom <SMCOM> -port <PORT_NAME> -auth <AUTH_NAME> -sctunn <SECURE_TUNNELING> -keyid <KEY_ID>
```

- Load host root CA certificate.
```
nxclitool certrepo-load-key -keytype rootca -keyid <KEY_ID> -curve <CURVE> -certtype <CERTIFICATE_TYPE> -in <FILE_NAME>
```

- Load device leaf key pair.
```
nxclitool certrepo-load-key -keytype leaf -keyid <KEY_ID> -curve <CURVE> -certtype <CERTIFICATE_TYPE> -in <FILE_NAME>
```

- Create a certificate repository.
```
nxclitool certrepo-create -repoid <REPO_ID> -keyid <KEY_ID> -wcomm full -rcomm full -waccess 0x0 -raccess 0x0 -kcomm na
```

- Load LEAF, P1 and P2 level device certificates.

```
nxclitool certrepo-load-cert -repoid <REPO_ID> -certlevel leaf -kcomm na -in <FILE_NAME>
nxclitool certrepo-load-cert -repoid <REPO_ID> -certlevel p1 -kcomm na -in <FILE_NAME>
nxclitool certrepo-load-cert -repoid <REPO_ID> -certlevel p2 -kcomm na -in <FILE_NAME>
```

- If the certificates are PKCS7 type, load host certificate mappings
  for LEAF, P1 and P2 levels. Skip this step if certificates are X509
  type.

```
nxclitool certrepo-load-mapping -repoid <REPO_ID> -certlevel leaf -kcomm na -in <FILE_NAME>
nxclitool certrepo-load-mapping -repoid <REPO_ID> -certlevel p1 -kcomm na -in <FILE_NAME>
nxclitool certrepo-load-mapping -repoid <REPO_ID> -certlevel p2 -kcomm na -in <FILE_NAME>
```

- Activate the certificate repository.
```
nxclitool certrepo-activate -repoid <REPO_ID> -kcomm na
```

- Disconnect from the SA.

```
./nxclitool disconnect
```

To verify the personalization, set the variable **NX_AUTH_CERT_DIR** to
the path to the certificates and run the ex_ecc example.

```
set NX_AUTH_CERT_DIR=<CERT_FOLDER_PATH>
<PATH_TO_EXECUTABLE>\ex_ecc.exe
```
## Set-Config I2C Management

set config i2c management like i2c support, i2c address
and select protocol options


**Command Format**
```
nxclitool set-i2c_mgnt [OPTIONS]
```

**Options**

-   **-i2csupport**: I2C disabled/enabled
-   **-i2caddr**: The address used for the I2C target (default 0x20):
-   **-protocoloptions**: The crypto protocols supported over I2C, refer NTAGECC_RefArch:

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool set-i2c_mgnt -i2csupport 0x01 -i2caddr 0x20 -protocoloptions 0x1B85
./nxclitool disconnect
```

## Set-Config Certificate Management

set config Certificate management like LeafCacheSize, IntermCacheSize, FeatureSelection
and ManageCertRepo-AccessCondition


**Command Format**
```
nxclitool set-cert_mgnt [OPTIONS]
```

**Options**

-   **-leafcachesize**: End Leaf certificate cache size 0x01...0x08
-   **-intermcachesize**: Intermediate certificate cache size 0x02...0x08
-   **-featureselection**: Enable SIGMA-I cache
    -   `0x01`: Enable SIGMA-I cache
    -   `0x00`: Disable SIGMA-I cache
-   **ManageCertRepoAccessCondition \[OPTIONS\]**
    -   **-wcomm**: ManageCertRepo communication mode. Accepted values:
        - `full`
        - `mac`
        - `plain`
        - `na`
    -   **-waccess**: Write Access Rights respectively. Accepted values:
        -   `0x00 to 0x0C`: Auth required
        -   `0x0D`: Free over I2C
        -   `0x0E`: Free Access
        -   `0x0F`: No Access

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool set-cert_mgnt -leafcachesize 0x08 -intermcachesize 0x08 -featureselection 0x01 -wcomm plain -waccess 0x00
./nxclitool disconnect
```

## Message-Digest with SA using NX CLI TooL

Generates a message digest or hash using the SA takes input data and produces a cryptographic hash using the selected algorithm SHA-256 

**Command Format**
```
nxclitool dgst-sha256 [OPTIONS]
```

**Options**
-   **-in**: Path to the plain input data in txt format
-   **-out**: Write the message digest to a file on this path

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool dgst-sha256 -in <INPUT_FILE_PATH> -out <DIGEST_FILE_PATH>
./nxclitool disconnect
```

## ECDSA Sign with SA using NX CLI TooL

Performs ECDSA signing using the SA signs the provided message digest using the private key associated with the given keyID

**Command Format**
```
nxclitool dgst-sign [OPTIONS]
```

**Options**

-   **-keyid**: Key ID for asymmetric keypair generation should be in HEX
    format. Range: **0x00 to 0x04**
-   **-in**: Path to the message digest file in txt format
-   **-out**: Path to save the generated signature

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool dgst-sign -keyid <KEY_ID> -in <DIGEST_FILE_PATH> -out <SIGNATURE_FILE_PATH> 
./nxclitool disconnect
```

## ECDSA Verify with SA using NX CLI TooL

Verifies an ECDSA signature using the SA Takes a message digest, a signature, and a public key to validate the authenticity of the signature

**Command Format**
```
nxclitool dgst-verify [OPTIONS]
```

**Options**

-   **-curve**: Curve type for ecdsa verify. Accepted values:
    - `brainpoolP256r1`: ECC curve type BRAINPOOL_256
    - `prime256v1`: ECC curve type NIST_P256
-   **-pubkey**: Path to the public key file in PEM format
-   **-signature**: Path to the signature file in txt format
-   **-in**: Path to the message digest file in txt format

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool dgst-verify -curve <CURVE> -pubkey <PUB_KEY_PATH> -signature <SIGNATURE_FILE> -in <DIGEST_FILE>
./nxclitool disconnect
```

## Derive ECDH with SA using NX CLI TooL

Derive an ecdh shared secret key using the keyID associated with a keypair stored in SA and peer's public key to compute the shared secret

**Command Format**
```
nxclitool derive-ecdh [OPTIONS]
```

**Options**

-   **-keyid**: Key ID for asymmetric key pair. Range: **0x00 to 0x04**
-   **-curve**: Curve type for asymmetric keypair. Accepted values:
    -   `brainpoolP256r1`: ECC curve type BRAINPOOL_256
    -   `prime256v1`: ECC curve type NIST_P256
-   **-pubkey**: Path to the peer public key file in PEM format
-   **-out**: Path to the save derived shared secret key file in DER format

**Example**

```
./nxclitool connect -smcom t1oi2c -port "/dev/i2c-1" -auth symmetric -sctunn ntag_aes128_ev2 -keyid 0x00
./nxclitool derive-ecdh -keyid <KEY_ID> -curve <CURVE> --peerkey <PEER_PUB_KEY> -out <SHARED_SECRET_KEY>
./nxclitool disconnect
```