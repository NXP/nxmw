# AWS Cloud Demo on FreeRTOS

This demo demonstrates connection to AWS IoT Console using
pre-provisioned device credentials and publish/subscribe procedure using
MQTT.

## Prerequisites

- Active AWS account
- MCUXpresso installed (for running aws demo on MCXN947)
- Any Serial communicator(Tera Term)

## Creating a device on AWS account

Refer - [**AWS Developer guide**](https://docs.aws.amazon.com/iot/latest/developerguide/iot-gs-first-thing.html)

>**Note:** The device certificate needs to be activated and attached to a policy that allows usage of this certificate.

## Creating and updating device keys and certificates to Secure Authenticator

- Before running the cloud_aws example the client key pair and certificate must be provisioned to the NX secure authenticator

- Build provisioning demo. Refer [**cloud aws provisioning**](../provisioning/readme.md).

## Building the Demo

- Build NX middleware stack. Refer `Create Build files` section in [**MCU_cmake build**](../../../doc/mcu_cmake/readme.md).

- To get the AWS IoT MQTT broker endpoint for your account, go to the AWS IoT console and in the left navigation pane choose Settings. Copy the endpoint listed under the "Device data endpoint"

- In the `nxmw/demos/ksdk/aws_jitr/aws_client_credential_keys.h` file, update the endpoint in the macro "clientcredentialMQTT_BROKER_ENDPOINT" and thing name in the macro "clientcredentialIOT_THING_NAME"

- Update cmake options to use freeRTOS ::
    - `NXMW_RTOS:STRING=FreeRTOS`

```` console
- Project : `cloud_provisioning_aws`
````

## Running the Demo

1.  Open a serial terminal on PC for OpenSDA serial device with these
    settings:

        - 115200 baud rate
        - 8 data bits
        - No parity
        - One stop bit
        - No flow control

2.  Connect the ethernet port of the board to a router for internet access (IP address
    to the board is assigned by the DHCP server). Make sure the
    connection on port 8883 is not blocked.

3.  Flash the program to the target board. Refer `Running the Example` section in [**MCU_cmake build**](../../../doc/mcu_cmake/readme.md)

## Console output

If everything is successful, the output will be similar to:
```
nx_mw :INFO :NX_PKG_v02.05.00_20250411
nx_mw :INFO :sss_ex_rtos_task Started.
nx_mw :INFO :cip (Len=22)
                01 04 63 07     00 93 02 08     00 02 03 E8     00 01 00 64
                04 03 E8 00     FE 00
nx_mw :INFO :Session Open Succeed
nx_mw :INFO :AWS subscribe publish example


Initializing PHY...
nx_mw :INFO :Getting IP address from DHCP ...

nx_mw :INFO :
 IPv4 Address     : 192.168.2.200

nx_mw :INFO :DHCP OK

[INFO] Create a TCP connection to a29rg0ytflhg6y.iot.eu-central-1.amazonaws.com:8883.
[INFO] (Network connection 0x20017be0) TLS handshake successful.
[INFO] (Network connection 0x20017be0) Connection to a29rg0ytflhg6y.iot.eu-central-1.amazonaws.com [INFO] MQTT connection established with the broker.
[INFO] MQTT connection successfully established with broker.


[INFO] A clean MQTT connection is established. Cleaning up all the stored outgoing publishes.


nx_mw :INFO :MQTT Connection successfully established
[INFO] Attempt to subscribe to the MQTT topic $aws/things/K64f_1/shadow/update/accepted.
nx_mw :INFO :MQTT Subscribed
[INFO] the published payload:{"msg" : "hello from SDK QOS0 : 0"}

[INFO] PUBLISH sent for topic sdkTest/sub to broker with packet ID 2.


nx_mw :INFO :Published message {"msg" : "hello from SDK QOS0 : 0"}
nx_mw :INFO :AWS demo passed
nx_mw :INFO :Demo Example Finished
```
