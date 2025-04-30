/*
 * Copyright 2024 NXP
 * SPDX-License-Identifier: BSD-3-Clause
**/

void nxclitool_show_command_help_rng()
{
    printf("\nUSAGE: nxclitool rand -bytes [NO_OF_BYTES]\n");
    printf("\n");
}

sss_status_t nxclitool_do_rng(nxclitool_sss_boot_ctx_t *pboot_ctx, nx_connect_ctx_t *pconn_ctx, size_t rng_bytes)
{
    sss_status_t status       = kStatus_SSS_Fail;
    size_t rng_data_len       = sizeof(uint8_t) * rng_bytes;
    uint8_t *rng_data         = malloc(rng_data_len);
    sss_rng_context_t ctx_rng = {0};
    if (rng_data == NULL) {
        LOG_E("Error in dynamic allocation!!");
        goto cleanup;
    }
    memset(rng_data, 0, rng_data_len);

    LOG_I("Requesting %d bytes of random data...", rng_bytes);

    status = sss_rng_context_init(&ctx_rng, &pboot_ctx->session);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    status = sss_rng_get_random(&ctx_rng, rng_data, rng_data_len);
    ENSURE_OR_GO_CLEANUP(status == kStatus_SSS_Success);

    LOG_I("Get Random Data successful!!!");
    LOG_MAU8_I("Generated random data:", rng_data, rng_data_len);

cleanup:
    if (rng_data) {
        free(rng_data);
    }
    sss_rng_context_free(&ctx_rng);
    return status;
}