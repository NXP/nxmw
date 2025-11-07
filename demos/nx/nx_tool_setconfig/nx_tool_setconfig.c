/*
*
* Copyright 2022-2025 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <limits.h>
#include "ex_sss_boot.h"
#include "fsl_sss_nx_apis.h"
#include "smCom.h"
#include "sm_apdu.h"
#include "nxLog_msg.h"
#include "nxEnsure.h"
#include "nx_tool_setconfig.h"
#include "nx_apdu.h"

static ex_sss_boot_ctx_t gex_sss_ecc_boot_ctx;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_ecc_boot_ctx)
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

#include <ex_sss_main_inc.h>

/**
 * set configuration according to command parameters
 *
 * \param[in] pCtx: if it's used for session.
 *
 * \retval ::SW_OK Upon successfull execution
 */
static sss_status_t nx_set_configure(
    ex_sss_boot_ctx_t *pCtx, uint32_t setConfigFlag, tool_setconfig_cmd_param_t *cmdParam)
{
    sss_status_t status                                      = kStatus_SSS_Fail;
    smStatus_t sm_status                                     = SM_NOT_OK;
    uint8_t acCryptoRequest                                  = 0;
    sss_nx_session_t *pSession                               = NULL;
    uint8_t cryptoAPISupport                                 = 0x00;
    uint8_t orgcryptoAPISupport                              = 0x00;
    uint8_t orgAcCryptoRequest                               = 0;
    uint8_t acChangeKey                                      = 0;
    uint8_t TBPolicyCount                                    = NX_TB_POLICY_MAX_COUNT;
    Nx_slot_buffer_policy_t TBPolicy[NX_TB_POLICY_MAX_COUNT] = {0};
    uint8_t SBPolicyCount                                    = NX_SB_POLICY_MAX_COUNT;
    Nx_slot_buffer_policy_t SBPolicy[NX_SB_POLICY_MAX_COUNT] = {0};
    uint32_t gpioCfgMask                                     = 0;
    Nx_gpio_config_t orggpioConfig                           = {0};
    Nx_gpio_config_t gpioConfig                              = {0};
    uint8_t orgkeyAC                                         = 0x00;
    uint8_t orgrootKeyAC                                     = 0x00;
    uint8_t keyAC                                            = 0x00;
    uint8_t rootKeyAC                                        = 0x00;

    ENSURE_OR_GO_EXIT((pCtx != NULL) && (cmdParam != NULL));
    pSession = (sss_nx_session_t *)&pCtx->session;

    // Set crypto API configuration
    if (setConfigFlag & (SET_CONFIG_CMD_FLAG_CRYPTO_COMM_MODE | SET_CONFIG_CMD_FLAG_CRYPTO_AC)) {
        sm_status = nx_GetConfig_CryptoAPIMgmt(&((sss_nx_session_t *)pSession)->s_ctx,
            &orgcryptoAPISupport,
            &orgAcCryptoRequest,
            &acChangeKey,
            &TBPolicyCount,
            &TBPolicy[0],
            &SBPolicyCount,
            &SBPolicy[0]);
        if (sm_status != SM_OK) {
            LOG_E("nx_GetConfig_CryptoAPIMgmt Failed");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        // support = (ASYM_CRYPTO_API_ENABLE | SYM_CRYPTO_API_ENABLE);
        cryptoAPISupport = NX_CONF_CRYPTOAPI_ASYMMETRIC_ENABLED | NX_CONF_CRYPTOAPI_SYMMETRIC_ENABLED;
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_CRYPTO_COMM_MODE) {
            acCryptoRequest |= cmdParam->cryptoAC;
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_CRYPTO_AC) {
            acCryptoRequest |= cmdParam->cryptoAC;
        }

        sm_status = nx_SetConfig_CryptoAPIMgmt(&((sss_nx_session_t *)pSession)->s_ctx,
            cryptoAPISupport,
            acCryptoRequest,
            acChangeKey,
            TBPolicyCount,
            TBPolicy,
            SBPolicyCount,
            SBPolicy);
        if (sm_status != SM_OK) {
            LOG_E("nx_SetConfig_CryptoAPIMgmt Failed");
            status = kStatus_SSS_Fail;
            goto exit;
        }
    }
    // Set GPIO configuration
    gpioCfgMask =
        SET_CONFIG_CMD_FLAG_GPIO1_MODE | SET_CONFIG_CMD_FLAG_GPIO2_MODE | SET_CONFIG_CMD_FLAG_GPIO2CONFIG |
        SET_CONFIG_CMD_FLAG_GPIO1_NOTIF | SET_CONFIG_CMD_FLAG_GPIO2_NOTIF | SET_CONFIG_CMD_FLAG_GPIO_MGMT_COMM_MODE |
        SET_CONFIG_CMD_FLAG_GPIO_MGMT_AC | SET_CONFIG_CMD_FLAG_GPIO_READ_COMM_MODE | SET_CONFIG_CMD_FLAG_GPIO_READ_AC |
        SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLA | SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLB | SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLC |
        SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLD | SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLA | SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLB |
        SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLC | SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLD |
        SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_FILENO | SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_OFFSET |
        SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_LENGTH;
    if (setConfigFlag & gpioCfgMask) {
        // Get current GPIO configuration and set to output mode.
        sm_status = nx_GetConfig_GPIOMgmt(&((sss_nx_session_t *)pSession)->s_ctx, &orggpioConfig);

        if (sm_status != SM_OK) {
            LOG_E("nx_GetConfig_GPIOMgmt Failed");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO1_MODE) {
            gpioConfig.gpio1Mode = cmdParam->gpio1Mode;
            if (gpioConfig.gpio1Mode == Nx_GPIOMgmtCfg_GPIOMode_Input) {
                gpioConfig.gpio1InputCfg = Nx_GPIOPadCfg_InputCfg_PlainInput_WeakPullUp;
            }
            else if (gpioConfig.gpio1Mode == Nx_GPIOMgmtCfg_GPIOMode_Output) {
                gpioConfig.gpio1OutputCfg = Nx_GPIOPadCfg_OutputCfg_GPIO_Low_Speed_1;
            }
            else if (gpioConfig.gpio1Mode == Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut) {
                gpioConfig.gpio1PowerOutDefaultTarget = Nx_GPIOMgmtCfg_VoltageCurrentLevel_1800mV_100uA;
            }
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO2_MODE) {
            gpioConfig.gpio2Mode = cmdParam->gpio2Mode;
            if (gpioConfig.gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_Input) {
                gpioConfig.gpio2InputCfg      = Nx_GPIOPadCfg_InputCfg_PlainInput_WeakPullUp;
                gpioConfig.gpio2OutputCfg     = Nx_GPIOPadCfg_OutputCfg_Output_disabled;
                gpioConfig.gpio2Supply1v1n1v2 = Nx_GPIOMgmtCfg_SupplySelection_1V8_Signaling_I2C;
            }
            else if (gpioConfig.gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_Output) {
                gpioConfig.gpio2OutputCfg = Nx_GPIOPadCfg_OutputCfg_GPIO_High_Speed_1;
            }
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO2CONFIG) {
            if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO2_MODE) {
                gpioConfig.gpio2Mode = cmdParam->gpio2Mode;
                if (gpioConfig.gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_Output ||
                    gpioConfig.gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_NfcPausefileOut) {
                    gpioConfig.gpio2OutputInitStateHigh = (cmdParam->gpio2Config & 1) ? true : false;
                }
                else if (gpioConfig.gpio2Mode == Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut) {
                    gpioConfig.gpio2PowerOutBackpowerEnabled = (cmdParam->gpio2Config & 1) ? true : false;
                    gpioConfig.gpio2PowerOutI2CEnabled       = ((cmdParam->gpio2Config >> 1) & 1) ? true : false;
                }
            }
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO1_NOTIF) {
            gpioConfig.gpio1OutputNotif = cmdParam->gpio1Notif;
            gpioConfig.gpio2OutputNotif = cmdParam->gpio2Notif;
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO_MGMT_COMM_MODE) {
            gpioConfig.acManage |= (cmdParam->gpioMgmtAC & NX_CONF_COMM_MODE_MASK);
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO_MGMT_AC) {
            gpioConfig.acManage |= (cmdParam->gpioMgmtAC & NX_CONF_AC_MASK);
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO_READ_COMM_MODE) {
            gpioConfig.acRead |= (cmdParam->gpioReadAC & NX_CONF_COMM_MODE_MASK);
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO_READ_AC) {
            gpioConfig.acRead |= (cmdParam->gpioReadAC & NX_CONF_AC_MASK);
        }

        // gpio1padctrlA
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLA) {
            gpioConfig.gpio1DebounceFilterValue =
                (orggpioConfig.gpio1DebounceFilterValue & 0xFF) | ((cmdParam->gpio1padctrlA & 0x03) << 8);
        }

        // gpio1padctrlB
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLB) {
            gpioConfig.gpio1DebounceFilterValue =
                (orggpioConfig.gpio1DebounceFilterValue & 0x300) | (cmdParam->gpio1padctrlB & 0xFF);
        }

        // gpio1padctrlC
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLC) {
            if (cmdParam->gpio1padctrlC_debounceSet) {
                gpioConfig.gpio1DebounceFilterEnabled = ((cmdParam->gpio1padctrlC >> 2) & 0x01);
            }
            if (cmdParam->gpio1padctrlC_inputFilterSet) {
                gpioConfig.gpio1InputFilterSelection = (Nx_GPIOPadCfg_InputFilter_t)(cmdParam->gpio1padctrlC & 0x03);
            }
        }

        // gpio1padctrlD
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLD) {
            if (cmdParam->gpio1padctrlD_inputCfgSet) {
                gpioConfig.gpio1InputCfg = (Nx_GPIOPadCfg_InputCfg_t)((cmdParam->gpio1padctrlD >> 5) & 0x07);
            }
            if (cmdParam->gpio1padctrlD_outputCfgSet) {
                gpioConfig.gpio1OutputCfg = (Nx_GPIOPadCfg_OutputCfg_t)((cmdParam->gpio1padctrlD >> 1) & 0x0F);
            }
            if (cmdParam->gpio1padctrlD_supplySet) {
                gpioConfig.gpio1Supply1v1n1v2 = (cmdParam->gpio1padctrlD & 0x01);
            }
        }

        // gpio2padctrlA
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLA) {
            gpioConfig.gpio2DebounceFilterValue =
                (orggpioConfig.gpio2DebounceFilterValue & 0xFF) | ((cmdParam->gpio2padctrlA & 0x03) << 8);
        }

        // gpio2padctrlB
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLB) {
            gpioConfig.gpio2DebounceFilterValue =
                (orggpioConfig.gpio2DebounceFilterValue & 0x300) | (cmdParam->gpio2padctrlB & 0xFF);
        }

        // gpio2padctrlC
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLC) {
            if (cmdParam->gpio2padctrlC_debounceSet) {
                gpioConfig.gpio2DebounceFilterEnabled = ((cmdParam->gpio2padctrlC >> 2) & 0x01);
            }
            if (cmdParam->gpio2padctrlC_inputFilterSet) {
                gpioConfig.gpio2InputFilterSelection = (Nx_GPIOPadCfg_InputFilter_t)(cmdParam->gpio2padctrlC & 0x03);
            }
        }

        // gpio2padctrlD
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLD) {
            if (cmdParam->gpio2padctrlD_inputCfgSet) {
                gpioConfig.gpio2InputCfg = (Nx_GPIOPadCfg_InputCfg_t)((cmdParam->gpio2padctrlD >> 5) & 0x07);
            }
            if (cmdParam->gpio2padctrlD_outputCfgSet) {
                gpioConfig.gpio2OutputCfg = (Nx_GPIOPadCfg_OutputCfg_t)((cmdParam->gpio2padctrlD >> 1) & 0x0F);
            }
            if (cmdParam->gpio2padctrlD_supplySet) {
                gpioConfig.gpio2Supply1v1n1v2 = (cmdParam->gpio2padctrlD & 0x01);
            }
        }

        // Update only if user provided
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_FILENO)
            gpioConfig.gpio2OutputNFCPauseFileNo = cmdParam->gpio2OutputNFCPauseFileNo;

        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_OFFSET)
            gpioConfig.gpio2OutputNFCPauseOffset = cmdParam->gpio2OutputNFCPauseOffset;

        if (setConfigFlag & SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_LENGTH)
            gpioConfig.gpio2OutputNFCPauseLength = cmdParam->gpio2OutputNFCPauseLength;

        sm_status = nx_SetConfig_GPIOMgmt(&((sss_nx_session_t *)pSession)->s_ctx, gpioConfig);
        if (sm_status != SM_OK) {
            LOG_E("nx_SetConfig_GPIOMgmt Failed");
            status = kStatus_SSS_Fail;
            goto exit;
        }
    }

    // Set ECC Key configuration
    if (setConfigFlag & (SET_CONFIG_CMD_FLAG_MGMT_KEYPAIR_COMM_MODE | SET_CONFIG_CMD_FLAG_MGMT_KEYPAIR_AC |
                            SET_CONFIG_CMD_FLAG_MGMT_CAROOT_KEY_COMM_MODE | SET_CONFIG_CMD_FLAG_MGMT_CAROOT_KEY_AC)) {
        sm_status = nx_GetConfig_EccKeyMgmt(&((sss_nx_session_t *)pSession)->s_ctx, &orgkeyAC, &orgrootKeyAC);
        if (sm_status != SM_OK) {
            LOG_E("nx_GetConfig_EccKeyMgmt Failed");
            status = kStatus_SSS_Fail;
            goto exit;
        }

        if (setConfigFlag & SET_CONFIG_CMD_FLAG_MGMT_KEYPAIR_COMM_MODE) {
            keyAC |= cmdParam->mgmtKeypairAC;
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_MGMT_KEYPAIR_AC) {
            keyAC |= cmdParam->mgmtKeypairAC;
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_MGMT_CAROOT_KEY_COMM_MODE) {
            rootKeyAC |= cmdParam->mgmtCARootKeyAC;
        }
        if (setConfigFlag & SET_CONFIG_CMD_FLAG_MGMT_CAROOT_KEY_AC) {
            rootKeyAC |= cmdParam->mgmtCARootKeyAC;
        }

        sm_status = nx_SetConfig_EccKeyMgmt(&((sss_nx_session_t *)pSession)->s_ctx, keyAC, rootKeyAC);
        if (sm_status != SM_OK) {
            LOG_E("nx_SetConfig_EccKeyMgmt Failed");
            status = kStatus_SSS_Fail;
            goto exit;
        }
    }
    if (sm_status == SM_OK) {
        status = kStatus_SSS_Success;
    }

exit:
    return status;
}

sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status    = kStatus_SSS_Fail;
    int argc               = gex_sss_argc;
    const char **argv      = gex_sss_argv;
    int parameter_error    = 1;
    uint32_t setconfigflag = 0;
    int index;
    tool_setconfig_cmd_param_t cmdParam = {0};
    long accessCondition                = 0;
    long gpioConfigCandidate            = 0;
    uint8_t value                       = 0;
    uint8_t consumed                    = 0;

    if ((argc >= 4) && (argc % 2 == 0)) { // cmd [-x param] ... [-x param] [COM]
        index = 1;
        while (index < (argc - 1)) {
            if (strcmp(argv[index], "-gpio1mode") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO1_MODE; //set gpio1 mode
                if (strcmp(argv[index + 1], "disabled") == 0) {
                    cmdParam.gpio1Mode = Nx_GPIOMgmtCfg_GPIOMode_Disabled;
                    parameter_error    = 0;
                }
                else if (strcmp(argv[index + 1], "input") == 0) {
                    cmdParam.gpio1Mode = Nx_GPIOMgmtCfg_GPIOMode_Input;
                    parameter_error    = 0;
                }
                else if (strcmp(argv[index + 1], "output") == 0) {
                    cmdParam.gpio1Mode = Nx_GPIOMgmtCfg_GPIOMode_Output;
                    parameter_error    = 0;
                }
                else if (strcmp(argv[index + 1], "tag") == 0) {
                    cmdParam.gpio1Mode = Nx_GPIOMgmtCfg_GPIOMode_InputTagTamper;
                    parameter_error    = 0;
                }
                else if (strcmp(argv[index + 1], "powerout") == 0) {
                    cmdParam.gpio1Mode = Nx_GPIOMgmtCfg_GPIOMode_DownstreamPowerOut;
                    parameter_error    = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-gpio2mode") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO2_MODE; //set gpio2 mode
                if (strcmp(argv[index + 1], "disabled") == 0) {
                    cmdParam.gpio2Mode = Nx_GPIOMgmtCfg_GPIOMode_Disabled;
                    parameter_error    = 0;
                }
                else if (strcmp(argv[index + 1], "input") == 0) {
                    cmdParam.gpio2Mode = Nx_GPIOMgmtCfg_GPIOMode_Input;
                    parameter_error    = 0;
                }
                else if (strcmp(argv[index + 1], "output") == 0) {
                    cmdParam.gpio2Mode = Nx_GPIOMgmtCfg_GPIOMode_Output;
                    parameter_error    = 0;
                }
                else if (strcmp(argv[index + 1], "out_nfcpausefile") == 0) {
                    cmdParam.gpio2Mode = Nx_GPIOMgmtCfg_GPIOMode_NfcPausefileOut;
                    parameter_error    = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-gpio1Notif") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO1_NOTIF; //set gpio notification
                if (strcmp(argv[index + 1], "disabled") == 0) {
                    cmdParam.gpio1Notif = Nx_GPIOMgmtCfg_GPIONotif_Disabled;
                    parameter_error     = 0;
                }
                else if (strcmp(argv[index + 1], "auth") == 0) {
                    cmdParam.gpio1Notif = Nx_GPIOMgmtCfg_GPIONotif_Auth;
                    parameter_error     = 0;
                }
                else if (strcmp(argv[index + 1], "nfc") == 0) {
                    cmdParam.gpio1Notif = Nx_GPIOMgmtCfg_GPIONotif_NFC;
                    parameter_error     = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-gpio2Notif") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO2_NOTIF; //set gpio notification
                if (strcmp(argv[index + 1], "disabled") == 0) {
                    cmdParam.gpio2Notif = Nx_GPIOMgmtCfg_GPIONotif_Disabled;
                    parameter_error     = 0;
                }
                else if (strcmp(argv[index + 1], "auth") == 0) {
                    cmdParam.gpio2Notif = Nx_GPIOMgmtCfg_GPIONotif_Auth;
                    parameter_error     = 0;
                }
                else if (strcmp(argv[index + 1], "nfc") == 0) {
                    cmdParam.gpio2Notif = Nx_GPIOMgmtCfg_GPIONotif_NFC;
                    parameter_error     = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-gpioMgmtCM") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO_MGMT_COMM_MODE; //set gpio manage commMode
                if (strcmp(argv[index + 1], "plain") == 0) {
                    cmdParam.gpioMgmtAC |= (Nx_CommMode_Plain << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "mac") == 0) {
                    cmdParam.gpioMgmtAC |= (Nx_CommMode_MAC << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "full") == 0) {
                    cmdParam.gpioMgmtAC |= (Nx_CommMode_FULL << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-gpioReadCM") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO_READ_COMM_MODE; //set gpio read commMode
                if (strcmp(argv[index + 1], "plain") == 0) {
                    cmdParam.gpioReadAC |= (Nx_CommMode_Plain << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "mac") == 0) {
                    cmdParam.gpioReadAC |= (Nx_CommMode_MAC << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "full") == 0) {
                    cmdParam.gpioReadAC |= (Nx_CommMode_FULL << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-gpioMgmtAC") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO_MGMT_AC; //set gpio manage access condition
                accessCondition = strtol(argv[index + 1], NULL, 16);
                if ((accessCondition >= 0) && (accessCondition <= 0xF)) {
                    cmdParam.gpioMgmtAC |= (uint8_t)accessCondition;
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-gpioReadAC") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO_READ_AC; //set gpio read access condition
                accessCondition = strtol(argv[index + 1], NULL, 16);
                if ((accessCondition >= 0) && (accessCondition <= 0xF)) {
                    cmdParam.gpioReadAC |= (uint8_t)accessCondition;
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-cryptoCM") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_CRYPTO_COMM_MODE; //set crypto API commMode
                if (strcmp(argv[index + 1], "plain") == 0) {
                    cmdParam.cryptoAC |= (Nx_CommMode_Plain << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "mac") == 0) {
                    cmdParam.cryptoAC |= (Nx_CommMode_MAC << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "full") == 0) {
                    cmdParam.cryptoAC |= (Nx_CommMode_FULL << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-cryptoAC") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_CRYPTO_AC; //set crypto API access condition
                accessCondition = strtol(argv[index + 1], NULL, 16);
                if ((accessCondition >= 0) && (accessCondition <= 0xF)) {
                    cmdParam.cryptoAC |= (uint8_t)accessCondition;
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-keypairCM") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_MGMT_KEYPAIR_COMM_MODE; //set ManageKeyPair commMode
                if (strcmp(argv[index + 1], "plain") == 0) {
                    cmdParam.mgmtKeypairAC |= (Nx_CommMode_Plain << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "mac") == 0) {
                    cmdParam.mgmtKeypairAC |= (Nx_CommMode_MAC << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "full") == 0) {
                    cmdParam.mgmtKeypairAC |= (Nx_CommMode_FULL << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-keypairAC") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_MGMT_KEYPAIR_AC; //set crypto API access condition
                accessCondition = strtol(argv[index + 1], NULL, 16);
                if ((accessCondition >= 0) && (accessCondition <= 0xF)) {
                    cmdParam.mgmtKeypairAC |= (uint8_t)accessCondition;
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-caRootKeyCM") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_MGMT_CAROOT_KEY_COMM_MODE; //set ManageCARootKey commMode
                if (strcmp(argv[index + 1], "plain") == 0) {
                    cmdParam.mgmtCARootKeyAC |= (Nx_CommMode_Plain << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "mac") == 0) {
                    cmdParam.mgmtCARootKeyAC |= (Nx_CommMode_MAC << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else if (strcmp(argv[index + 1], "full") == 0) {
                    cmdParam.mgmtCARootKeyAC |= (Nx_CommMode_FULL << NX_COMM_MODE_BIT_SHIFT);
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else if (strcmp(argv[index], "-caRootKeyAC") == 0) {
                setconfigflag |= SET_CONFIG_CMD_FLAG_MGMT_CAROOT_KEY_AC; //set ManageCARootKey condition
                accessCondition = strtol(argv[index + 1], NULL, 16);
                if ((accessCondition >= 0) && (accessCondition <= 0xF)) {
                    cmdParam.mgmtCARootKeyAC |= (uint8_t)accessCondition;
                    parameter_error = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            // gpio2config
            else if (strcmp(argv[index], "-gpio2config") == 0) {
                gpioConfigCandidate = strtoul(argv[index + 1], NULL, 0);
                if ((gpioConfigCandidate >= 0) && (gpioConfigCandidate <= 0x03)) {
                    setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO2CONFIG;
                    cmdParam.gpio2Config = (uint8_t)gpioConfigCandidate;
                    parameter_error      = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            // gpio1padctrlA
            else if (strcmp(argv[index], "-gpio1padctrlA") == 0) {
                gpioConfigCandidate = strtoul(argv[index + 1], NULL, 0);
                if ((gpioConfigCandidate >= 0) && (gpioConfigCandidate <= 0x03)) {
                    setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLA;
                    cmdParam.gpio1padctrlA = (uint8_t)gpioConfigCandidate;
                    parameter_error        = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }

                index += 2;
            }

            // gpio1padctrlB
            else if (strcmp(argv[index], "-gpio1padctrlB") == 0) {
                gpioConfigCandidate = strtoul(argv[index + 1], NULL, 0);
                if ((gpioConfigCandidate >= 0) && (gpioConfigCandidate <= 0xFF)) {
                    setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLB;
                    cmdParam.gpio1padctrlB = (uint8_t)gpioConfigCandidate;
                    parameter_error        = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }

                index += 2;
            }

            // gpio1padctrlC
            else if (strcmp(argv[index], "-gpio1padctrlC") == 0) {
                value            = 0;
                consumed         = 1;
                bool debounceSet = false, inputFilterSet = false;

                for (int i = index + 1; i < argc && argv[i][0] != '-'; i++) {
                    if (strcmp(argv[i], "debounce_enable") == 0) {
                        value |= (1 << 2);
                        debounceSet = true;
                    }
                    else if (strcmp(argv[i], "debounce_disable") == 0) {
                        value |= (0 << 2);
                        debounceSet = true;
                    }
                    else if (strcmp(argv[i], "input_unfiltered_50ns") == 0) {
                        value |= 0x00;
                        inputFilterSet = true;
                    }
                    else if (strcmp(argv[i], "input_unfiltered_10ns") == 0) {
                        value |= 0x01;
                        inputFilterSet = true;
                    }
                    else if (strcmp(argv[i], "input_zif_50ns") == 0) {
                        value |= 0x02;
                        inputFilterSet = true;
                    }
                    else if (strcmp(argv[i], "input_zif_10ns") == 0) {
                        value |= 0x03;
                        inputFilterSet = true;
                    }
                    if ((UINT8_MAX - 1) < consumed) {
                        goto exit;
                    }
                    consumed++;
                }

                cmdParam.gpio1padctrlC                = value;
                cmdParam.gpio1padctrlC_debounceSet    = debounceSet;
                cmdParam.gpio1padctrlC_inputFilterSet = inputFilterSet;
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLC;
                index += consumed;
            }

            // gpio1padctrlD
            else if (strcmp(argv[index], "-gpio1padctrlD") == 0) {
                value            = 0;
                consumed         = 1;
                bool inputCfgSet = false, outputCfgSet = false, supplySet = false;

                for (int i = index + 1; i < argc && argv[i][0] != '-'; i++) {
                    if (strcmp(argv[i], "input_plain_pullup") == 0) {
                        value |= (0x00 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_plain_repeater") == 0) {
                        value |= (0x01 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_plain") == 0) {
                        value |= (0x02 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_plain_pulldown") == 0) {
                        value |= (0x03 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_weak_pullup") == 0) {
                        value |= (0x04 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_weak_pulldown") == 0) {
                        value |= (0x05 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_high_z") == 0) {
                        value |= (0x06 << 5);
                        inputCfgSet = true;
                    }

                    else if (strcmp(argv[i], "gpio_low_speed_1") == 0) {
                        value |= (0x04 << 1);
                        outputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "gpio_low_speed_2") == 0) {
                        value |= (0x05 << 1);
                        outputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "gpio_high_speed_1") == 0) {
                        value |= (0x06 << 1);
                        outputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "gpio_high_speed_2") == 0) {
                        value |= (0x07 << 1);
                        outputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "output_disabled") == 0) {
                        value |= (0x08 << 1);
                        outputCfgSet = true;
                    }

                    else if (strcmp(argv[i], "supply_1v8") == 0) {
                        value |= 0x00;
                        supplySet = true;
                    }
                    else if (strcmp(argv[i], "supply_1v1") == 0) {
                        value |= 0x01;
                        supplySet = true;
                    }
                    if ((UINT8_MAX - 1) < consumed) {
                        goto exit;
                    }
                    consumed++;
                }

                cmdParam.gpio1padctrlD              = value;
                cmdParam.gpio1padctrlD_inputCfgSet  = inputCfgSet;
                cmdParam.gpio1padctrlD_outputCfgSet = outputCfgSet;
                cmdParam.gpio1padctrlD_supplySet    = supplySet;
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLD;
                index += consumed;
            }
            // gpio2padctrlA
            else if (strcmp(argv[index], "-gpio2padctrlA") == 0) {
                gpioConfigCandidate = strtoul(argv[index + 1], NULL, 0);
                if ((gpioConfigCandidate >= 0) && (gpioConfigCandidate <= 0x03)) {
                    setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLA;
                    cmdParam.gpio2padctrlA = (uint8_t)gpioConfigCandidate;
                    parameter_error        = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }

            // gpio2padctrlB
            else if (strcmp(argv[index], "-gpio2padctrlB") == 0) {
                gpioConfigCandidate = strtoul(argv[index + 1], NULL, 0);
                if ((gpioConfigCandidate >= 0) && (gpioConfigCandidate <= 0xFF)) {
                    setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLB;
                    cmdParam.gpio2padctrlB = (uint8_t)gpioConfigCandidate;
                    parameter_error        = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }

                index += 2;
            }

            // gpio2padctrlC
            else if (strcmp(argv[index], "-gpio2padctrlC") == 0) {
                value            = 0;
                consumed         = 1;
                bool debounceSet = false, inputFilterSet = false;

                for (int i = index + 1; i < argc && argv[i][0] != '-'; i++) {
                    if (strcmp(argv[i], "debounce_enable") == 0) {
                        value |= (1 << 2);
                        debounceSet = true;
                    }
                    else if (strcmp(argv[i], "debounce_disable") == 0) {
                        value |= (0 << 2);
                        debounceSet = true;
                    }
                    else if (strcmp(argv[i], "input_unfiltered_50ns") == 0) {
                        value |= 0x00;
                        inputFilterSet = true;
                    }
                    else if (strcmp(argv[i], "input_unfiltered_10ns") == 0) {
                        value |= 0x01;
                        inputFilterSet = true;
                    }
                    else if (strcmp(argv[i], "input_zif_50ns") == 0) {
                        value |= 0x02;
                        inputFilterSet = true;
                    }
                    else if (strcmp(argv[i], "input_zif_10ns") == 0) {
                        value |= 0x03;
                        inputFilterSet = true;
                    }
                    if ((UINT8_MAX - 1) < consumed) {
                        goto exit;
                    }
                    consumed++;
                }

                cmdParam.gpio2padctrlC                = value;
                cmdParam.gpio2padctrlC_debounceSet    = debounceSet;
                cmdParam.gpio2padctrlC_inputFilterSet = inputFilterSet;
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLC;
                index += consumed;
            }

            // gpio2padctrlD
            else if (strcmp(argv[index], "-gpio2padctrlD") == 0) {
                value            = 0;
                consumed         = 1;
                bool inputCfgSet = false, outputCfgSet = false, supplySet = false;

                for (int i = index + 1; i < argc && argv[i][0] != '-'; i++) {
                    if (strcmp(argv[i], "input_plain_pullup") == 0) {
                        value |= (0x00 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_plain_repeater") == 0) {
                        value |= (0x01 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_plain") == 0) {
                        value |= (0x02 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_plain_pulldown") == 0) {
                        value |= (0x03 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_weak_pullup") == 0) {
                        value |= (0x04 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_weak_pulldown") == 0) {
                        value |= (0x05 << 5);
                        inputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "input_high_z") == 0) {
                        value |= (0x06 << 5);
                        inputCfgSet = true;
                    }

                    else if (strcmp(argv[i], "gpio_low_speed_1") == 0) {
                        value |= (0x04 << 1);
                        outputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "gpio_low_speed_2") == 0) {
                        value |= (0x05 << 1);
                        outputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "gpio_high_speed_1") == 0) {
                        value |= (0x06 << 1);
                        outputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "gpio_high_speed_2") == 0) {
                        value |= (0x07 << 1);
                        outputCfgSet = true;
                    }
                    else if (strcmp(argv[i], "output_disabled") == 0) {
                        value |= (0x08 << 1);
                        outputCfgSet = true;
                    }

                    else if (strcmp(argv[i], "supply_1v8") == 0) {
                        value |= 0x00;
                        supplySet = true;
                    }
                    else if (strcmp(argv[i], "supply_1v1") == 0) {
                        value |= 0x01;
                        supplySet = true;
                    }
                    if ((UINT8_MAX - 1) < consumed) {
                        goto exit;
                    }
                    consumed++;
                }

                cmdParam.gpio2padctrlD              = value;
                cmdParam.gpio2padctrlD_inputCfgSet  = inputCfgSet;
                cmdParam.gpio2padctrlD_outputCfgSet = outputCfgSet;
                cmdParam.gpio2padctrlD_supplySet    = supplySet;
                setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLD;
                index += consumed;
            }
            // NFCPauseFileNo
            else if (strcmp(argv[index], "-nfcpausefileno") == 0) {
                gpioConfigCandidate = strtoul(argv[index + 1], NULL, 0);
                if ((gpioConfigCandidate >= 0) && (gpioConfigCandidate <= 0x1F)) {
                    setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_FILENO; // NFC Pause is tied to GPIO2 mode
                    cmdParam.gpio2OutputNFCPauseFileNo = (uint8_t)gpioConfigCandidate;
                    parameter_error                    = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }

            // NFCPauseOffset
            else if (strcmp(argv[index], "-nfcpauseoffset") == 0) {
                gpioConfigCandidate = strtoul(argv[index + 1], NULL, 0);
                if ((gpioConfigCandidate >= 0) && (gpioConfigCandidate <= 0xFFFFFF)) {
                    setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_OFFSET;
                    cmdParam.gpio2OutputNFCPauseOffset = (uint32_t)gpioConfigCandidate;
                    parameter_error                    = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }

            // NFCPauseLength
            else if (strcmp(argv[index], "-nfcpauselength") == 0) {
                gpioConfigCandidate = strtoul(argv[index + 1], NULL, 0);
                if ((gpioConfigCandidate >= 0) && (gpioConfigCandidate <= 0xFFFFFF)) {
                    setconfigflag |= SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_LENGTH;
                    cmdParam.gpio2OutputNFCPauseLength = (uint32_t)gpioConfigCandidate;
                    parameter_error                    = 0;
                }
                else {
                    parameter_error = 1;
                    break;
                }
                index += 2;
            }
            else {
                parameter_error = 1;
                break;
            }
        }
    }
    else {
        parameter_error = 1;
    }

    if (parameter_error) {
        LOG_I("\nUSAGE:\n");
        LOG_I("  %s [-gpio1mode {disabled|input|output|tag|powerout}]", gex_sss_argv[0]);
        LOG_I(
            "     [-gpio2mode {disabled|input|output|out_nfcpausefile}] [-gpio1Notif {disabled|auth|nfc}] [-gpio2Notif "
            "{disabled|auth|nfc}][-gpioMgmtCM "
            "{plain|mac|full}]");
        LOG_I("     [-gpioReadCM {plain|mac|full}] [-gpioMgmtAC {0x0-0xF}] [-gpioReadAC {0x0-0xF}]");
        LOG_I("     [-cryptoCM {plain|mac|full}] [-cryptoAC {0x0-0xF}]");
        LOG_I("     [-keypairCM {plain|mac|full}] [-keypairAC {0x0-0xF}]");
        LOG_I("     [-caRootKeyCM {plain|mac|full}] [-caRootKeyAC {0x0-0xF}]");
        LOG_I(
            "     [-gpio2config {gpio2mode is output or outputwithnfcpausefile 0x00-0x01| gpio2mode power down stream "
            "0x00-0x03}]");
        LOG_I("     [-gpio1padctrlA <0x00-0x03>] [-gpio1padctrlB <0x00-0xFF>]");
        LOG_I(
            "     [-gpio1padctrlC "
            "{debounce_enable|debounce_disable|input_unfiltered_50ns|input_unfiltered_10ns|input_zif_50ns|input_zif_"
            "10ns}]");
        LOG_I(
            "     [-gpio1padctrlD "
            "{input_plain_pullup|input_plain_repeater|input_plain|input_plain_pulldown|input_weak_pullup|input_weak_"
            "pulldown|input_high_z|");
        LOG_I(
            "                      "
            "gpio_low_speed_1|gpio_low_speed_2|gpio_high_speed_1|gpio_high_speed_2|output_disabled|supply_1v8|supply_"
            "1v1}]");
        LOG_I("     [-gpio2padctrlA <0x00-0x03>] [-gpio2padctrlB <0x00-0xFF>]");
        LOG_I(
            "     [-gpio2padctrlC "
            "{debounce_enable|debounce_disable|input_unfiltered_50ns|input_unfiltered_10ns|input_zif_50ns|input_zif_"
            "10ns}]");
        LOG_I(
            "     [-gpio2padctrlD "
            "{input_plain_pullup|input_plain_repeater|input_plain|input_plain_pulldown|input_weak_pullup|input_weak_"
            "pulldown|input_high_z|");
        LOG_I(
            "                      "
            "gpio_low_speed_1|gpio_low_speed_2|gpio_high_speed_1|gpio_high_speed_2|output_disabled|supply_1v8|supply_"
            "1v1}]");

        LOG_I(
            "     [-nfcpausefileno <0x00-0x1F>] [-nfcpauseoffset <0x000000-0xFFFFFF>] [-nfcpauselength "
            "<0x000000-0xFFFFFF>] <port_name>\n");

        LOG_I("  Example: %s -gpio1mode output \"NXP Semiconductors P71 T=0, T=1 Driver 0\"\n", gex_sss_argv[0]);
        goto exit;
    }

    status = nx_set_configure(pCtx, setconfigflag, &cmdParam);
    if (status != kStatus_SSS_Success) {
        LOG_E("SET Config Failed.");
        goto exit;
    }

exit:

    if (kStatus_SSS_Success == status) {
        LOG_I("SET config Example Success !!!...");
    }
    else {
        LOG_E("SET config Example Failed !!!...");
    }

    return status;
}
