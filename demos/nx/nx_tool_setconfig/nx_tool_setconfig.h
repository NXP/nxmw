/* Copyright 2022-2023,2025 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __NX_SETCONFIG__
#define __NX_SETCONFIG__

#define ASYM_CRYPTO_API_ENABLE 0x02
#define SYM_CRYPTO_API_ENABLE 0x01

#define STANDARD_FILE_NUM 0x00
#define ISO_FILE_ID 0x0001

#define SET_CONFIG_CMD_FLAG_GPIO1_MODE (1 << 1)
#define SET_CONFIG_CMD_FLAG_GPIO2_MODE (1 << 2)
#define SET_CONFIG_CMD_FLAG_GPIO1_NOTIF (1 << 3)
#define SET_CONFIG_CMD_FLAG_GPIO2_NOTIF (1 << 14)
#define SET_CONFIG_CMD_FLAG_GPIO_MGMT_COMM_MODE (1 << 4)
#define SET_CONFIG_CMD_FLAG_GPIO_MGMT_AC (1 << 5)
#define SET_CONFIG_CMD_FLAG_GPIO_READ_COMM_MODE (1 << 6)
#define SET_CONFIG_CMD_FLAG_GPIO_READ_AC (1 << 7)
#define SET_CONFIG_CMD_FLAG_CRYPTO_COMM_MODE (1 << 8)
#define SET_CONFIG_CMD_FLAG_CRYPTO_AC (1 << 9)
#define SET_CONFIG_CMD_FLAG_MGMT_KEYPAIR_COMM_MODE (1 << 10)
#define SET_CONFIG_CMD_FLAG_MGMT_KEYPAIR_AC (1 << 11)
#define SET_CONFIG_CMD_FLAG_MGMT_CAROOT_KEY_COMM_MODE (1 << 12)
#define SET_CONFIG_CMD_FLAG_MGMT_CAROOT_KEY_AC (1 << 13)
#define SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLA (1 << 14)
#define SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLB (1 << 15)
#define SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLC (1 << 16)
#define SET_CONFIG_CMD_FLAG_GPIO1_PADCTRLD (1 << 17)
#define SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLA (1 << 18)
#define SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLB (1 << 19)
#define SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLC (1 << 20)
#define SET_CONFIG_CMD_FLAG_GPIO2_PADCTRLD (1 << 21)
#define SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_FILENO (1 << 22)
#define SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_OFFSET (1 << 23)
#define SET_CONFIG_CMD_FLAG_GPIO_NFCPAUSE_LENGTH (1 << 24)
#define SET_CONFIG_CMD_FLAG_GPIO2CONFIG (1 << 25)

typedef struct _tool_setconfig_cmd_param_t
{
    Nx_GPIOMgmtCfg_GPIOMode_t gpio1Mode;
    Nx_GPIOMgmtCfg_GPIOMode_t gpio2Mode;
    uint8_t gpio2Config;
    Nx_GPIOMgmtCfg_GPIONotif_t gpio1Notif;
    Nx_GPIOMgmtCfg_GPIONotif_t gpio2Notif;
    uint8_t gpioMgmtAC;
    uint8_t gpioReadAC;
    uint8_t cryptoAC;
    uint8_t mgmtKeypairAC;
    uint8_t mgmtCARootKeyAC;

    // GPIO1 PadCtrl
    uint8_t gpio1padctrlA;
    uint8_t gpio1padctrlB;
    uint8_t gpio1padctrlC;
    uint8_t gpio1padctrlD;

    bool gpio1padctrlC_debounceSet;
    bool gpio1padctrlC_inputFilterSet;

    bool gpio1padctrlD_inputCfgSet;
    bool gpio1padctrlD_outputCfgSet;
    bool gpio1padctrlD_supplySet;

    // GPIO2 PadCtrl
    uint8_t gpio2padctrlA;
    uint8_t gpio2padctrlB;
    uint8_t gpio2padctrlC;
    uint8_t gpio2padctrlD;

    bool gpio2padctrlC_debounceSet;
    bool gpio2padctrlC_inputFilterSet;

    bool gpio2padctrlD_inputCfgSet;
    bool gpio2padctrlD_outputCfgSet;
    bool gpio2padctrlD_supplySet;

    uint8_t gpio2OutputNFCPauseFileNo;  // FileNo (0x00..0x1F)
    uint32_t gpio2OutputNFCPauseOffset; // Offset (0x000000..0xFFFFFF)
    uint32_t gpio2OutputNFCPauseLength; // Length (0x000000..0xFFFFFF)

} tool_setconfig_cmd_param_t;

static sss_status_t nx_set_configure(
    ex_sss_boot_ctx_t *pCtx, uint32_t setConfigFlag, tool_setconfig_cmd_param_t *cmdParam);

#endif
