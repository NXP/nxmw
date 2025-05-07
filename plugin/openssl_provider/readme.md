# OpenSSL Provider for NX Secure Authenticator

A provider, in OpenSSL terms, is a unit of code that provides one or more
implementations for various operations for diverse algorithms that one might
want to perform.

Depending on the capabilities of the attached secure authenticator,
the following functionality can be made available over the OpenSSL provider here (sssProvider).

- EC crypto
  - EC key generation
  - EC sign/verify
  - ECDH compute key
  - CSR
- Random generator

The OpenSSL provider is compatible with OpenSSL versions 3.0.x

OpenSSL provider is tested on i.MX (imx8mqevk, with yocto), Raspberry Pi (Raspberry Pi 4 Model B, Ubuntu 22.04.2 LTS)


## Getting Started on Raspberry Pi

### Prerequisite

- Raspberry pi
- cmake installed: ``sudo apt-get install cmake``
- OpenSSL 3.0.x installed
- SA connected to Raspberry Pi on i2c port


### Build
Run the commands below to build OpenSSL provider for NX secure authenticator

```
git clone ssh://git@bitbucket.sw.nxp.com/kmw/nxmw-github.git
cd scripts
python create_cmake_projects.py
cd ../../nxmw_build/raspbian_native_nx_t1oi2c
cmake -DNXMW_OpenSSL=3_0 -DWithSharedLIB=OFF -DNXMW_All_Auth_Code=Enabled .
sudo make all
sudo make install
sudo ldconfig /usr/local/lib
```

Above commands will build the OpenSSL provider and NX CLI tool (used for provisioning the SA) and copy it in ``plugin/openssl_provider/bin`` and ``binaries/tmp`` folders respectively.

## Testing OpenSSL Provider

### Random Number Generation

```
openssl rand --provider /usr/local/lib/libsssProvider.so -hex 32

```

### ECC (Nist256) Key Generation

```
mkdir output
openssl ecparam --provider /usr/local/lib/libsssProvider.so --provider default -name prime256v1:0x02 -genkey -noout -out output/nx_prime256v1_ref.pem -propquery "provider=nxp_prov"

```

The above command will generate the key in secure authenticator at 0x02 keyid and the output ``nx_prime256v1_ref.pem`` is the reference to the key location of secure authenticator. Refer **"Referencing keys in the secure authenticator"** section on this page for more details.

The reference key can also be used to perform further crypto operation with secure authenticator.

Supported curves
  - prime256v1 (secp256r1)
  - brainpoolP256r1

>**Note:** <span style="color:blue;">
The key will be generated with default policy i.e. only sign enabled.
</span>

>**Note:** <span style="color:blue;">
Key generation on secure authenticator using nxp provider can be done only by loading nxp provider with highest priority.
</span>

>**Note:** <span style="color:blue;">
Rest of the commands in this section which require an EC key will assume that a key is present at key ID 0x02 and "nx_prime256v1_ref.pem" is the corresponding reference key.
</span>

### ECDSA - Sign Operation

```
mkdir input_data
echo "Hello Word" > input_data/input_data.txt
openssl pkeyutl --provider /usr/local/lib/libsssProvider.so --provider default -inkey nxp:0x02 -sign -rawin -in input_data/input_data.txt -out output/signature.bin -digest sha256

```

In case the default provider is loaded first, ensure to pass the correct property query. Example -

```
openssl pkeyutl --provider default --provider /usr/local/lib/libsssProvider.so -inkey nxp:0x02 -sign -rawin -in input_data/input_data.txt -out output/signature.bin -digest sha256 -propquery "?nxp_prov.signature.ecdsa=yes"

```

Refer - 'OSSL Algorithms property definitions' section for more details.


### ECDSA - Verify Operation

```
#Extract public key from reference key
openssl ec -in output/nx_prime256v1_ref.pem -pubout -out output/pubkey.pem

openssl pkeyutl -verify --provider default -inkey output/pubkey.pem -pubin -rawin -in input_data/input_data.txt -sigfile output/signature.bin -digest sha256

```
>**Note:** <span style="color:blue;">
Here verify operation is performed by host and not the SA as SA does not have public key required for this operation stored inside.
</span>

### ECDH Operation

Provisioning of an EC key (with ECDH policy enabled) should be done first before performing ECDH operation using the python script [**openssl_provision.py**](./scripts/openssl_provision.py). This script will inject an EC key inside SA at key ID 0x03 for ECDH operation. This script uses NX CLI tool to provision and assumes that the nxclitool binary is present at ``binaries/tmp`` (refer: [**NX CLI Tool**](../../demos/nx/nx_cli_tool/readme.md)).

```
cd plugin/openssl_provider/scripts
mkdir output
# Peer key is created on host
openssl ecparam -name prime256v1 -genkey -noout -out output/peer_key.pem

# Extract public key from peer key
openssl ec -in output/peer_key.pem -pubout -out output/peer_public_key.pem

# Assume off chip EC key generation
openssl ecparam -name prime256v1 -genkey -noout -out output/ec_key.pem

# Provisions ec_key.pem inside SA with ECDH policy enabled at Key ID 0x03
python openssl_provision.py -smcom t1oi2c -port /dev/i2c-1 -curve prime256v1 -keypath output/ec_key.pem

openssl pkeyutl -derive --provider /usr/local/lib/libsssProvider.so --provider default -inkey nxp:0x03 -peerkey output/peer_public_key.pem -hexdump -out output/ecdh_key.bin

```


## Referencing keys in the secure authenticator

The keys created inside secure authenticator can be referenced in 3 different ways

1. Reference Keys in file format
2. Labels with reference key. Example - nxp:"path to reference key file"
3. Labels with key id. Example - nxp:0x12345678

### 1. Reference Keys in file format

The cryptographic functionality offered by the OpenSSL provider requires a reference to a key stored inside the secure authenticator (exception is random generation).

OpenSSL requires a key pair, consisting of a private and a public key, to be loaded before the cryptographic operations can be executed. This creates a challenge when OpenSSL is used in combination with a secure authenticator as the private key cannot be extracted out from the secure authenticator.

The solution is to populate the OpenSSL Key data structure with only a reference to the private key inside the secure authenticator instead of the actual private key. The public key as read from the secure authenticator can still be inserted into the key structure.

OpenSSL crypto APIs are then invoked with these data structure objects as parameters. When the crypto API is routed to the provider, the NX OpenSSL provider implementation decodes these key references and invokes the secure authenticator APIs with correct key references for a cryptographic operation. If the input key is not a reference key, execution will roll back to OpenSSL software implementation.

>**Note:** <span style="color:blue;">When using this method, the sss provider has to be loaded first. This will ensure that the sss provider can decode the key id information present in the reference key.
</span>


#### EC Reference Key Format

The following provides an example of an EC reference key. The value reserved
for the private key has been used to contain:

-  a pattern of ``0x10..00`` to fill up the data structure MSB side to the
   desired key length
-  a 32 bit key identifier (in the example below ``0x7DCCBBAA``)
-  a 64 bit magic number (always ``0xA5A6B5B6A5A6B5B6``)
-  a byte to describe the key class (``0x10`` for Key pair and ``0x20`` for
   Public key)
-  a byte to describe the key index (use a reserved value ``0x00``)

```
Private-Key: (256 bit)
priv:
   10:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
   00:00:00:7D:CC:BB:AA:A5:A6:B5:B6:A5:A6:B5:B6:
   kk:ii
pub:
   04:1C:93:08:8B:26:27:BA:EA:03:D1:BE:DB:1B:DF:
   8E:CC:87:EF:95:D2:9D:FC:FC:3A:82:6F:C6:E1:70:
   A0:50:D4:B7:1F:F2:A3:EC:F8:92:17:41:60:48:74:
   F2:DB:3D:B4:BC:2B:F8:FA:E8:54:72:F6:72:74:8C:
   9E:5F:D3:D6:D4
ASN1 OID: prime256v1
```

---
- The key identifier ``0x7DCCBBAA`` (stored in big-endian convention) is in
  front of the magic number ``0xA5A6B5B6A5A6B5B6``
- The padding of the private key value and the magic number make it
  unlikely a normal private key value matches a reference key.
- Ensure the value reserved for public key and ASN1 OID contain the values
  matching the stored key.
---

### 2. Labels with reference key.

In this method, the reference key file (described in previous section) with full path can be passed in string format with "nxp:" as prefix.
Example - nxp:"path to reference key file".

>**Note:** <span style="color:blue;">When using this approach, there is no need to load the sss provider first. Default provider can have the higher priority.</span>


### 3. Labels with key id.

In this method, the 4 byte key id of the Key created / stored in secure authenticator is passed as is in string format with "nxp:" as prefix.
Example - nxp:0x12345678

>**Note:** <span style="color:blue;">When using this approach, there is no need to load the sss provider first. Default provider can have the higher priority.</span>


## OSSL Algorithms property definitions

Following properties definitions are added in nxp provider(see file ../provider/src/sssProvider_main.c),

  - Random number generation - `nxp_prov.rand=yes`

  - Key management - `nxp_prov.keymgmt=yes` (Required to offload the ECC operations to nxp provider when the keys are stored in NX secure authenticator).

  - Signature - `nxp_prov.signature=yes`  (Required to offload the ECC / Verify operations to nxp provider when the keys are stored in NX secure authenticator).

  - ECDH - `nxp_prov.keyexch=yes` (Required only when the ephemeral keys are generated on NX).

  - Key Store - `nxp_prov.store=yes`  (Required when the keys are referenced using label (nxp:) or reference keys).
    - For keys passed with nxp: prefix - `nxp_prov.store.nxp=yes`
    - For keys passed with reference key format - `nxp_prov.store.file=yes`


## Testing OpenSSL Provider

The directory ``plugin/openssl_provider/scripts`` contains a set of python scripts.
These scripts use the OpenSSL provider in the context of standard
OpenSSL utilities. They illustrate using the OpenSSL provider for fetching
random data and EC crypto operations. Before using the scripts except openssl_EccGenKey.py, an EC key needs to be provisioned in SA. This can be done using [**openssl_provision.py**](scripts/openssl_provision.py) which provisions the EC key at key ID 0x02 with signing policy enabled and at key ID 0x04 with ECDH policy enabled.


```
# ECC Key generation
python openssl_EccGenKey.py  --key_type prime256v1 --connection_data /dev/i2c-1

# ECC CSR and certificate creation
python openssl_EccCSR.py --key_type prime256v1 --connection_data /dev/i2c-1

# Provision EC key inside SA
python openssl_provision.py -smcom t1oi2c -port /dev/i2c-1 -curve prime256v1 -keypath ../keys/prime256v1/ecc_key_kp.pem

# Random number generation
python openssl_rnd.py --connection_data /dev/i2c-1

# ECDSA Operations
python openssl_EccSign.py --key_type prime256v1 --connection_data /dev/i2c-1

# ECDH Key generation
python openssl_Ecdh.py --key_type prime256v1 --connection_data /dev/i2c-1

```


## TLS Client example using provider

This section explains how to set-up a TLS link using the NX OpenSSL Provider on the client side.
The TLS demo demonstrates setting up a mutually authenticated and encrypted link between a client and a server system.

The key pair used to identify the client is created / stored in the secure authenticator.

The key pair used to identify the server is simply available as a pem file.

The public keys associated with the respective key pairs are contained in respectively a client and a server certificate.

The CA is a self-signed certificate. The same CA is used to sign client and server certificate.

### TLS1.2 / TLS1.3 client example using EC keys

Create client and server credentials as shown below

```
openssl ecparam -name prime256v1 -out prime256v1.pem


# Create Root CA key pair and certificate
openssl ecparam -in prime256v1.pem -genkey -noout -out tls_rootca_key.pem
openssl req -x509 -new -nodes -key tls_rootca_key.pem -subj /OU="NXP Plug Trust CA/CN=NXP RootCAvRxxx" -days 4380 -out tls_rootca.cer


# Create client key inside secure authenticator
openssl ecparam --provider /usr/local/lib/libsssProvider.so --provider default -name prime256v1:0x02 -genkey -out tls_client_key_ref_0x02.pem


# Create Client key CSR. Use the provider to access the client key created in the previous file.
openssl req --provider /usr/local/lib/libsssProvider.so --provider default -new -key tls_client_key_ref_0x02.pem -subj "/CN=NXP_NX_SA_TLS_CLIENT_ECC" -out tls_client.csr


# Create Client certificate
openssl x509 -req -sha256 -days 4380 -in tls_client.csr -CAcreateserial -CA tls_rootca.cer -CAkey tls_rootca_key.pem -out tls_client.cer


# Create Server key pair and certificate
openssl ecparam -in prime256v1.pem -genkey -noout -out tls_server_key.pem
openssl req -new -key tls_server_key.pem -subj "/CN=NXP_TLS_SERVER_ECC" -out tls_server.csr
openssl x509 -req -sha256 -days 4380 -in tls_server.csr -CAcreateserial -CA tls_rootca.cer -CAkey tls_rootca_key.pem -out tls_server.cer

```

Run Server as

```
openssl s_server -accept 8080 -no_ssl3 -named_curve prime256v1  -CAfile tls_rootca.cer  -cert tls_server.cer -key tls_server_key.pem -cipher ECDHE-ECDSA-AES128-SHA256 -Verify 2 -state -msg
```

Run Client as

```
openssl s_client --provider /usr/local/lib/libsssProvider.so --provider default -connect 127.0.0.1:8080 -tls1_2 -CAfile tls_rootca.cer -cert tls_client.cer -key tls_client_key_ref_0x02.pem -cipher ECDHE-ECDSA-AES128-SHA256 -state -msg
```
OR
```
openssl s_client --provider /usr/local/lib/libsssProvider.so --provider default -connect 127.0.0.1:8080 -tls1_3 -CAfile tls_rootca.cer -cert tls_client.cer -key tls_client_key_ref_0x02.pem -state -msg
```

## OpenSSL Configuration file

The provider can be loaded via OpenSSL configuration file also.
Changes required in configuration file to load provider is shown below,

```
...

openssl_conf = openssl_init
config_diagnostics = 1

[openssl_init]
providers = provider_sect

[provider_sect]
nxp_prov = nxp_sect
default = default_sect

[nxp_sect]
identity = nxp_prov
module = <provider lib path>
activate = 1

[default_sect]
activate = 1

...
```

The order in which the providers are written in `[provider_sect]` section, defines the priority of the providers loaded.
The one included first, will have the higher priority.


>**Note:** <span style="color:blue;">It is not recommended to modify the default OpenSSL config file. Create a new config file to load custom providers and set the OPENSSL_CONF env variable to config file path. Example:
    export OPENSSL_CONF=<CONFIG_FILE_PATH>
</span>
