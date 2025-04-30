/*
 * Amazon FreeRTOS V1.4.1
 * Copyright (C) 2017 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * http://aws.amazon.com/freertos
 * http://www.FreeRTOS.org
 */

/*
 *
 * Copyright 2024 NXP
 */

#ifndef AWS_CREDENTIAL_KEYS_H
#define AWS_CREDENTIAL_KEYS_H

#ifdef __GNUC__
#define USED __attribute__((used))
#else
#define USED
#endif
/*
 * Not Used for se_hostlib
 */

static const char keyCLIENT_CERTIFICATE_PEM[] = {0};

/*
 */
static const char *USED keyJITR_DEVICE_CERTIFICATE_AUTHORITY_PEM = "";

/*
 * Not Used for se_hostlib
 */
static const char keyCLIENT_PRIVATE_KEY_PEM[] = {0};

/*
 * MQTT Broker endpoint.
 */
static const char clientcredentialMQTT_BROKER_ENDPOINT[] = "a29rg0ytflhg6y.iot.eu-central-1.amazonaws.com";

/* Use of a "define" and not a "static const" here to be able to
* use pre-compile concatenation on the string. */
#define clientcredentialIOT_THING_NAME "K64f_1"

/*
 * Port number the MQTT broker is using.
 */
#define clientcredentialMQTT_BROKER_PORT 8883

/*
 * Port number the Green Grass Discovery use for JSON retrieval from cloud is using.
 */
#define clientcredentialGREENGRASS_DISCOVERY_PORT 8443

/*
 * WIFI network to join.
 */
#define clientcredentialWIFI_SSID "Paste WiFi SSID here."

/*
 * Password needed to join WiFi network.
 */
#define clientcredentialWIFI_PASSWORD "Paste WiFi password here."

/**
 * @brief Security type
 * WPA2 Security, @see WIFISecurity_t
 * other values are - eWiFiSecurityOpen, eWiFiSecurityWEP, eWiFiSecurityWPA
 */
#define clientcredentialWIFI_SECURITY eWiFiSecurityWPA2

/*
 * Length of device certificate included from aws_clientcredential_keys.h .
 */
static const uint32_t clientcredentialCLIENT_CERTIFICATE_LENGTH = sizeof(keyCLIENT_CERTIFICATE_PEM);

/*
 * Length of device private key included from aws_clientcredential_keys.h .
 */

static const uint32_t clientcredentialCLIENT_PRIVATE_KEY_LENGTH = sizeof(keyCLIENT_PRIVATE_KEY_PEM);

#endif
