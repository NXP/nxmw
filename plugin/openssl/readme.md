# Introduction on OpenSSL engine

Starting with OpenSSL 0.9.6 an 'Engine interface' was added to OpenSSL
allowing support for alternative cryptographic implementations. This
Engine interface can be used to interface with external crypto devices.
The key injection process is secure module specific and is not covered
by the Engine interface.

Following functionality can be made available over the OpenSSL Engine
interface:

- EC crypto
    - EC sign/verify
    - ECDH compute key
- Fetching random data


## OpenSSL versions

The OpenSSL Engine is compatible with OpenSSL versions 1.1.1.

## Platforms

The OpenSSL engine can be used on Raspberry Pi (running Raspbian).

## Keys

### Key Management

The cryptographic functionality offered by the OpenSSL engine requires a
reference to a key stored inside the Secure Authenticator (exception is
RAND_Method). These keys are typically inserted into the Secure
Authenticator in a secured environment during production.

OpenSSL requires a key pair, consisting of a private and a public key,
to be loaded before the cryptographic operations can be executed. This
creates a challenge when OpenSSL is used in combination with a Secure
Authenticator as the private key cannot be extracted out from the Secure
Authenticator.

The solution is to populate the OpenSSL Key data structure with only a
reference to the Private Key inside the Secure Authenticator instead of
the actual Private Key. The public key as read from the Secure
Authenticator can still be inserted into the key structure.

OpenSSL crypto API's are then invoked with these data structure objects
as parameters. When the crypto API is routed to the Engine, the OpenSSL
engine implementation decodes these key references and invokes the SSS
API with correct Key references for a cryptographic operation. If the
input key is not reference key, execution will roll back to OpenSSL
software implementation

### EC Reference key format

The following provides an example of an EC reference key. The value
reserved for the private key has been used to contain:

-   a pattern of `0x10..00` to fill up the data structure MSB side to the
    desired key length
-   a 32 bit key identifier (in the example below `0x00000002`)
-   a 64 bit magic number (always `0xA5A6B5B6A5A6B5B6`)
-   a byte to describe the key class (`0x10` for Key pair and `0x20` for
    Public key)
-   a byte to describe the key index (use a reserved value `0x00`)

```
Private-Key: (256 bit)
priv:
    10:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
    00:00:00:00:00:00:02:A5:A6:B5:B6:A5:A6:B5:B6:
    kk:ii
pub:
    04:1C:93:08:8B:26:27:BA:EA:03:D1:BE:DB:1B:DF:
    8E:CC:87:EF:95:D2:9D:FC:FC:3A:82:6F:C6:E1:70:
    A0:50:D4:B7:1F:F2:A3:EC:F8:92:17:41:60:48:74:
    F2:DB:3D:B4:BC:2B:F8:FA:E8:54:72:F6:72:74:8C:
    9E:5F:D3:D6:D4
ASN1 OID: prime256v1
```


**Note:**

The key identifier `0x00000002` (stored in big-endian convention) is
in front of the magic number `0xA5A6B5B6A5A6B5B6` - The padding of the
private key value and the magic number make it unlikely a normal private
key value matches a reference key. - Ensure the value reserved for
public key and ASN1 OID contain the values matching the stored key.


## Building the OpenSSL engine

Refer [**Linux build**](../../doc/linux/readme.md)

Select CMake options:
- `NXMW_HostCrypto=OPENSSL`
- `NXMW_OpenSSL=1_1_1`

Project: `sss_engine`

The cmake build system will create an OpenSSL engine for supported
platforms. The resulting OpenSSL engine will be copied to the SW tree in
directory `nx-mw-top/plugin/openssl/bin`.

Ensure the following flag is defined when building an application that
will be linked against the engine: `-DOPENSSL_LOAD_CONF`


## Sample scripts to demo OpenSSL Engine

The directory `nx-mw-top/plugin/openssl/scripts` ([**here**](./scripts/)) contains a set of
python scripts. These scripts use the OpenSSL Engine in the context of
standard OpenSSL utilities. They illustrate using the OpenSSL Engine for
fetching random data and supported EC crypto operations. The scripts that illustrate
EC crypto operations depend on prior provisioning of the Secure
Authenticator.

The python script [**openssl_provision.py**](./scripts/openssl_provision.py)
can be used to provision the SA with required key,

```
python openssl_provision.py -smcom <SMCOM> -port <PORT_NAME> -curve <CURVE> -keypath <PATH_TO_KEY>
```

Some keys are placed in the path `nx-mw-top/plugin/openssl/keys` for demonstration purpose. User can provision the SA for OpenSSL Engine using following command:
```
cd nx-mw-top/plugin/openssl/scripts
python openssl_provision.py -smcom t1oi2c -port /dev/i2c-1 -curve prime256v1 -keypath ../keys/prime256v1/ecc_key_kp.pem
```

**NOTE:**
- The provisioning script uses NX CLI Tool to provision the SA and assumes some of the inputs to the CLI tool for simplicity. For e.g. `NXMW_Secure_Tunneling` is set to `NTAG_AES128_EV2` and `NXMW_Auth` is set to `SYMM_Auth` by default and, these can be changed in the script as per user's preference.
- This script provisions the key with signing policy enabled at key ID 0x02 and the key with ECDH policy enabled at ID 0x03. User must make sure no other keys are present in these key IDs before provisioning.


To generate the random numbers, invoke following script:

```
cd nx-mw-top/plugin/openssl/scripts
python3 openssl_rnd.py --connection_data none
```

The following set of commands invokes the OpenSSL Provider for ECDSA
sign/verify operations and ECDH calculations:

```
python3 openssl_EccSign.py --key_type prime256v1
python3 openssl_Ecdh.py --key_type prime256v1
```
