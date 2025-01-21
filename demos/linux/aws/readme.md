
AWS Demo for RaspberryPi
========================

This demo demonstrates connection to AWS IoT Console using
pre-provisioned device credentials and publish/subscribe procedure using
MQTT.


## Prerequisites

-   AWS account setup (Refer -
    <https://docs.aws.amazon.com/iot/latest/developerguide/iot-gs-first-thing.html>)
-   Raspberry Pi with Raspbian OS, connected to the Internet
-   OpensSSL 1.1 installed


## Secure Authenticator preparation (client side)

For the purpose of this demo one MUST inject the client key pair into
the Secure Authenticator and use a reference pem file referring to the
provisioned key pair.

The python script
(`nx-mw-top/demos/linux/aws/aws_provisioning_client/aws_provision_client.py`) can be used to provision the SA with required key

```
python aws\provision\client.py -smcom <SMCOM> -port <PORT NAME> -keypath <PATH TO KEY>
```

The above commands will provision the client key at location 0x02 with the following policies.

``` {.sourceCode .c}
.sdmEnabled      = 0,
.sigmaiEnabled   = 0,
.ecdhEnabled     = 0,
.eccSignEnabled  = 1,
.writeCommMode   = kCommModeSSSFull,
.writeAccessCond = NxAccessConditionAuthRequired0x1,
.userCommMode    = kCommModeSSSNA,
```

The required reference key is manually created / stored for the demo at located - `nx-mw-top/demos/linux/aws/aws_provisioning_client/credentials/nxdevicekey.pem`

Build the OpenSSL engine
------------------------

The OpenSSL engine uses the sss abstraction layer to access the crypto
services of the Secure Authenticator. The following illustrates
compiling the OpenSSL engine for Nx connected over I2C.

```
cd nx-mw-top/scripts
python create_cmake_projects.py
cd ../../nx-mw-top_build/raspbian_native_nx_t1oi2c
cmake -DNXMW_OpenSSL:STRING=1_1_1 .
cmake --build .
make install
ldconfig /usr/local/lib
```

Run the example
---------------

1. Clone the code :

```
cd nx-mw-top/demos/linux/aws/
git clone https://github.com/aws/aws-iot-device-sdk-cpp.git
```

If curl is not installed, run - `sudo apt-get install libcurl4-openssl-dev`


2. Modify the `CMakeLists.txt` file under `samples/PubSub` so it
    ensures `OPENSSLLOADCONF` is defined (see excerpt below):

```
if (UNIX AND NOT APPLE)
    ADDDEFINITIONS(-DOPENSSLLOADCONF)
    # Prefer pthread if found
    set(THREADSPREFERPTHREADFLAG ON)
    set(CUSTOMCOMPILERFLAGS "-fno-exceptions -Wall -Werror")
elseif (APPLE)
    set(CUSTOMCOMPILERFLAGS "-fno-exceptions -Wall -Werror")
elseif (WIN32)
    set(CUSTOMCOMPILERFLAGS "/W4")
endif ()
```


3. Use 'buildScript.sh' script at nx-mw-top/demos/linux/aws/ to build the mqtt application:

```
./buildScript.sh
```


4. Adapt the PubSub example specific configuration file so that it refers to the reference key and the device certificate.

  - Update the endpoint to match your AWS account

  - Ensure the AmazonRootCA1.pem certificate is in place (it is
used by the rpi to validate the AWS IoT counterpart)

  - Update the configuration file (nx-mw-top/demos/linux/aws/aws-iot-device-sdk-cpp/build/bin/config/SampleConfig.json)
  with endpoint, device\certificate\relative\path, device\private\key\relative\path (Ensure the value for \"endpoint\" matches your setup,
  you must replace \"xxxxiukfoyyyy-ats.iot.eu-central-1.amazonaws.com\")

-   Sample Json file :

```
{
"endpoint": "xxxxiukfoyyyy-ats.iot.eu-central-1.amazonaws.com",
"mqttport": 8883,
"httpsport": 443,
"greengrassdiscoveryport": 8443,
"rootcarelativepath": "certs/AmazonRootCA1.pem",
"devicecertificaterelativepath": "nxdevicecertificate.cer",
"deviceprivatekeyrelativepath": "nxdevicereferencekey.pem",
"tlshandshaketimeoutmsecs": 60000,
"tlsreadtimeoutmsecs": 2000,
"tlswritetimeoutmsecs": 2000,
"awsregion": "",
"awsaccesskeyid": "",
"awssecretaccesskey": "",
"awssessiontoken": "",
"clientid": "CppSDKTesting",
"thingname": "CppSDKTesting",
"iscleansession": true,
"mqttcommandtimeoutmsecs": 20000,
"keepaliveintervalsecs": 600,
"minimumreconnectintervalsecs": 1,
"maximumreconnectintervalsecs": 128,
"maximumackstowaitfor": 32,
"actionprocessingratehz": 5,
"maximumoutgoingactionqueuelength": 32,
"discoveractiontimeoutmsecs": 300000
}
```

5. Set the OpenSSL config path as call:

```
$ export OPENSSLCONF=<nx-mw-top/-path>/demos/linux/common/openssl_sss_nx.cnf
```

6. Upload the root certificate to AWS account.

7. Run the application:

```
cd nx-mw-top/demos/linux/aws/aws-iot-device-sdk-cpp/build/bin
./pub-sub-sample
```
