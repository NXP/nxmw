/*
*
* Copyright 2022-2024 NXP
* SPDX-License-Identifier: BSD-3-Clause
*/

#include <stddef.h>
#include <assert.h>
#include <string.h>
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
    gpioCfgMask = SET_CONFIG_CMD_FLAG_GPIO1_MODE | SET_CONFIG_CMD_FLAG_GPIO2_MODE | SET_CONFIG_CMD_FLAG_GPIO1_NOTIF |
                  SET_CONFIG_CMD_FLAG_GPIO2_NOTIF | SET_CONFIG_CMD_FLAG_GPIO_MGMT_COMM_MODE |
                  SET_CONFIG_CMD_FLAG_GPIO_MGMT_AC | SET_CONFIG_CMD_FLAG_GPIO_READ_COMM_MODE |
                  SET_CONFIG_CMD_FLAG_GPIO_READ_AC;
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
            "     [-gpio2mode {disabled|input|output}] [-gpio1Notif {disabled|auth|nfc}] [-gpio2Notif "
            "{disabled|auth|nfc}][-gpioMgmtCM "
            "{plain|mac|full}]");
        LOG_I("     [-gpioReadCM {plain|mac|full}] [-gpioMgmtAC {0x0-0xF}] [-gpioReadAC {0x0-0xF}]");
        LOG_I("     [-cryptoCM {plain|mac|full}] [-cryptoAC {0x0-0xF}]");
        LOG_I("     [-keypairCM {plain|mac|full}] [-keypairAC {0x0-0xF}]");
        LOG_I("     [-caRootKeyCM {plain|mac|full}] [-caRootKeyAC {0x0-0xF}] <port_name>\n");

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
