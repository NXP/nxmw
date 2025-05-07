# OpenSSL Engine: TLS Client example

This section explains how to set-up a TLS link using the SSS OpenSSL
Engine on the client side.

## Summary

The TLS demo demonstrates setting up a mutually authenticated and
encrypted link between a client and a server system. The keypair used to
identify the client is stored in the Secure Authenticator. The keypair
used to identify the server is simply available as a pem file.

The public keys associated with the respective key pairs are contained
in respectively a client and a server certificate.

The CA is a self-signed certificate. The same CA is used to sign client
and server certificate.

## Secure Authenticator preparation (client side)

For the purpose of the demo one MUST inject the TLS client key pair into
the Secure Authenticator and use a reference pem file
(refer: [**EC Reference Key Format**](../../../plugin/openssl/readme.md)) referring to the provisioned key pair.

The python script [**tlsProvision.py**](./scripts/tlsProvision.py) (inside scripts folder) can be
used to provision the SA with required key.

Generic command:
```
python tlsProvision_sa.py -smcom <SMCOM> -port <PORT_NAME> -curve <CURVE> -keypath <PATH_TO_KEY>
```

The script will provision the client key at location 0x02 (for nist256) / 0x03 (for brainpool256p) with the following policies

```
.sdmEnabled      = 0,
.sigmaiEnabled   = 0,
.ecdhEnabled     = 0,
.eccSignEnabled  = 1,
.writeCommMode   = kCommMode_SSS_Full,
.writeAccessCond = Nx_AccessCondition_Auth_Required_0x1,
.userCommMode    = kCommMode_SSS_NA,
```

The required key is manually created / stored for the demo at located - `demos/nx/tls_client/credentials/<key_type>/tls_client_key.pem`

On RPI, you can use following command:
```
cd nxmw/demos/nx/tls_client/scripts
python tlsProvision.py -smcom t1oi2c -port /dev/i2c-1 -curve prime256v1 -keypath ../credentials/prime256v1/tls_client_key.pem
```
>**Note:** <span style="color:blue;">This command will store the key [**tls_client_key.pem**](./credentials/prime256v1/tls_client_key.pem) inside the SA at key ID 0x02.</span>

## Start up the server

>**Note:** <span style="color:blue;">The server can run e.g. on a PC. The server must be reachable over the TCP/IP network for the Client.</span>

Server can be executed using the following generic command:
```
python tlsServer.py <ECDHE|ECDHE_SHA256|max> <prime256v1(default)|brainpoolP256r1>
```

Execute the following command on the server platform to use the EC based
server credentials, make a note of the IP address of the server:

```
cd nxmw/demos/nx/tls_client/scripts
python tlsServer.py ECDHE_SHA256 prime256v1
```
## Establish a TLS link from the client to the server

- Build OpenSSL Engine (refer: [**Building the OpenSSL engine**](../../../plugin/openssl/readme.md))
- Invoke the script [**tlsSeClient.py**](./scripts/tlsSeClient.py) in a separate terminal using the IP address of the server as the first argument and ECDHE or ECDHE_SHA256 as the second argument (ECDHE
corresponding to ECDH ephemeral) when connecting to a server using EC
based credentials. Generic command:
```
python tlsSeClient.py <SERVER_IP_ADDRESS> <ECDHE|ECDHE_256>
```

Execute following command in a separate terminal to run TLS client:
```
cd nxmw/demos/nx/tls_client/scripts
python tlsSeClient.py 127.0.0.1 ECDHE_SHA256 prime256v1
```
Any message entered on the client terminal now will be received by server terminal and vice versa.