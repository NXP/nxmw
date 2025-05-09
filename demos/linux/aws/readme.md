
AWS Demo for RaspberryPi
========================

This demo demonstrates connection to AWS IoT Console using
pre-provisioned device credentials and publish/subscribe procedure using
MQTT.


## Prerequisites

-   AWS account setup (Refer -
    <https://docs.aws.amazon.com/iot/latest/developerguide/iot-gs-first-thing.html>)
-   Raspberry Pi with Raspbian OS, connected to the Internet
-   OpensSSL 1.1 or OpenSSL 3.x installed


## Secure Authenticator preparation (client side)

For the purpose of this demo one MUST inject the client key pair into
the Secure Authenticator and use a reference pem file referring to the
provisioned key pair.

The python script
(`nxmw/demos/linux/aws/aws_provisioning_client/aws_provision_client.py`) can be used to provision the SA with required key

```
python aws_provision_client.py -smcom <SMCOM> -port <PORT NAME> -keypath <PATH TO KEY>
```
>**Note:**  Path to the key to be provisioned - `nxmw/demos/linux/aws/aws_provisioning_client/credentials/nx_device_key.pem`

>**Note:**  Build `nxclitool` before running provisioning script. Refer [**Build nxclitool**](../../nx/nx_cli_tool//readme.md).

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

The required reference key is manually created / stored for the demo at location - `nxmw/demos/linux/aws/aws_provisioning_client/credentials/nx_device_reference_key.pem`

Build the OpenSSL engine (Required if using OpenSSL 1.x)
--------------------------------------------------------

The OpenSSL engine uses the sss abstraction layer to access the crypto
services of the Secure Authenticator. The following illustrates
compiling the OpenSSL engine for Nx connected over I2C.

```
cd nxmw/scripts
python create_cmake_projects.py
cd ../../nxmw_build/raspbian_native_nx_t1oi2c
cmake -DNXMW_OpenSSL:STRING=1_1_1 .
cmake --build .
make install
ldconfig /usr/local/lib
```

Build the OpenSSL Provider (Required if using OpenSSL 3.x.x)
------------------------------------------------------------

The OpenSSL provider uses the sss abstraction layer to access the crypto
services of the Secure Authenticator. The following illustrates
compiling the OpenSSL provider for Nx connected over I2C.

>**Note:** comment the following lines in `nxmw/plugin/openssl_provider/provider/src/sssProvider_main.c` before building OpenSSL Provider

```
    //if (NULL == OSSL_PROVIDER_load(NULL, "default")) {
    //     sssProv_Print(LOG_FLOW_ON, "error in OSSL_PROVIDER_load \n");
    // }
```

```
cd nxmw/scripts
python create_cmake_projects.py
cd ../../nxmw_build/raspbian_native_nx_t1oi2c
cmake -DNXMW_Auth=None -DNXMW_OpenSSL:STRING=3_0 -DNXMW_Secure_Tunneling=None -DNXMW_SMCOM=JRCP_V1_AM .
cmake --build .
make install
ldconfig /usr/local/lib
```

>**Note:** If OpenSSL Provider is used to run the demo, Use Access Manager to establish connection with Secure Authenticator. For details, refer [**Build and Run Access Manager**](../nx_access_manager/readme.md).

Run the example
---------------

1. Clone the aws-sdk :

    ```
    cd nxmw/demos/linux/aws/
    git clone https://github.com/aws/aws-iot-device-sdk-cpp.git
    ```

2. For the demo to build with openssl 3.x.x and to use sssProvider apply the patch to repo aws-iot-device-sdk-cpp
    ```
    cd nxmw/demos/linux/aws/aws-iot-device-sdk-cpp
    patch -p1 < ../sssProvider_Updates.patch
    ```

3. Modify the `CMakeLists.txt` file under `aws-iot-device-sdk-cpp/samples/PubSub` so it
    ensures `OPENSSL_LOAD_CONF` is defined (see excerpt below):

    ```
    if (UNIX AND NOT APPLE)
        ADD_DEFINITIONS(-DOPENSSL_LOAD_CONF)
        # Prefer pthread if found
        set(THREADSPREFERPTHREADFLAG ON)
        set(CUSTOMCOMPILERFLAGS "-fno-exceptions -Wall -Werror")
    elseif (APPLE)
        set(CUSTOMCOMPILERFLAGS "-fno-exceptions -Wall -Werror")
    elseif (WIN32)
        set(CUSTOMCOMPILERFLAGS "/W4")
    endif ()
    ```

>**Note:** If curl is not installed - run ``sudo apt-get install libcurl4-openssl-dev``

4. Set the permissions to `buildScript.sh` at `nxmw/demos/linux/aws/`:
    ```
    chmod 777 buildScript.sh
    ```

5. Use 'buildScript.sh' script to build the mqtt application:

    ```
    ./buildScript.sh
    ```

6. Adapt the PubSub example specific configuration file so that it refers to the reference key and the device certificate.

    - Update the endpoint to match your AWS account

    - Ensure the AmazonRootCA1.pem certificate is in place (it is
    used by the rpi to validate the AWS IoT counterpart)

    - Update the configuration file (nxmw/demos/linux/aws/aws-iot-device-sdk-cpp/build/bin/config/SampleConfig.json)
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

7. To run the demo with OpenSSL Provider, search for `provider_sect` in ``/nxmw/demos/linux/common/openssl30_sss_se050.cnf`` file and set the nxp provider with high priority.
    ```
    nxp_prov = nxp_prov_sec
    default = default_sect
    ```
8. Based on OpenSSL version, select the appropriate configuration file in
   ``/nxmw/demos/linux/common`` directory::

        openssl_sss_se050.cnf     ----- OpenSSL 1.x
        openssl30_sss_se050.cnf   ----- OpenSSL 3.x.x

9. Upload the root certificate to AWS account.

10. Run access manager (Required only if using OpenSSL Provider)

    ```
    cd nxmw_build/raspbian_native_nx_t1oi2c/bin
    ./accessManager
    ```

    >**Note:** Run Access Manager only when you use OpenSSL Provider.

11. Open New Terminal and set the OpenSSL config path as call:

    ```
    $ export OPENSSL_CONF=nxmw/demos/linux/common/<appropriate-cnf-file>
    ```

12. Run the application

    ```
    cd nxmw/demos/linux/aws/aws-iot-device-sdk-cpp/build/bin
    export EX_SSS_BOOT_SSS_PORT=<port_name>
    ./pub-sub-sample
    ```

>**Note:** When using Openssl Provider application will not connect to NX Secure Authenticator directly over i2c. It will connect to access manager which in turn will connect to SA over i2c. So export the port_name as `127.0.0.1:8040`.

>**Note:** If OpenSSL Engine is used no need to export port since the application will directly connect to Secure Authenticator over i2c.
