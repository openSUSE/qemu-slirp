/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates. (http://www.meta.com)
 */

/*
 * This test verifies slirp responses to NC-SI commands.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "slirp.h"
#include "ncsi-pkt.h"

#define NCSI_RESPONSE_CAPACITY 1024

static void test_ncsi_get_version_id(Slirp *slirp)
{
    slirp->mfr_id = 0xabcdef01;

    uint8_t command[] = {
        /* Destination MAC */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        /* Source MAC */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        /* Ethertype */
        0x88, 0xf8,
        /* NC-SI Control packet header */
        0x00, /* MC ID */
        0x01, /* Header revision */
        0x00, /* Reserved */
        0x01, /* Instance ID */
        0x15, /* Control Packet Type */
        0x00, /* Channel ID */
        0x00, /* Reserved */
        0x00, /* Payload length */
        0x00, 0x00, 0x00, 0x00, /* Reserved */
        0x00, 0x00, 0x00, 0x00, /* Reserved */
    };
    slirp_input(slirp, command, sizeof(command));

    const struct ncsi_rsp_gvi_pkt *gvi = slirp->opaque + ETH_HLEN;

    assert(ntohs(gvi->rsp.code) == NCSI_PKT_RSP_C_COMPLETED);
    assert(ntohs(gvi->rsp.code) == NCSI_PKT_RSP_R_NO_ERROR);
    assert(ntohl(gvi->mf_id) == slirp->mfr_id);

    slirp->mfr_id = 0;
}

static void test_ncsi_oem_mlx_unsupported_command(Slirp *slirp)
{
    uint8_t command[] = {
        /* Destination MAC */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        /* Source MAC */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        /* Ethertype */
        0x88, 0xf8,
        /* NC-SI Control packet header */
        0x00, /* MC ID */
        0x01, /* Header revision */
        0x00, /* Reserved */
        0x01, /* Instance ID */
        0x50, /* Control Packet Type */
        0x00, /* Channel ID */
        0x00, /* Reserved */
        0x08, /* Payload length */
        0x00, 0x00, 0x00, 0x00, /* Reserved */
        0x00, 0x00, 0x00, 0x00, /* Reserved */
        /* NC-SI OEM packet header */
        0x00, 0x00, 0x81, 0x19, /* Manufacturer ID: Mellanox */
        /* Vendor Data */
        0xff, /* Command Revision */
        0xff, /* Command ID */
        0x00, /* Parameter */
        0x00, /* Optional data */
    };
    const struct ncsi_rsp_oem_pkt *oem = slirp->opaque + ETH_HLEN;

    slirp->mfr_id = 0x00000000;
    slirp_input(slirp, command, sizeof(command));

    assert(ntohs(oem->rsp.code) == NCSI_PKT_RSP_C_UNSUPPORTED);
    assert(ntohs(oem->rsp.reason) == NCSI_PKT_RSP_R_UNKNOWN);
    assert(ntohl(oem->mfr_id) == 0x8119);

    slirp->mfr_id = 0x8119;
    slirp_input(slirp, command, sizeof(command));

    assert(ntohs(oem->rsp.code) == NCSI_PKT_RSP_C_UNSUPPORTED);
    assert(ntohs(oem->rsp.reason) == NCSI_PKT_RSP_R_UNKNOWN);
    assert(ntohl(oem->mfr_id) == 0x8119);
}

static ssize_t send_packet(const void *buf, size_t len, void *opaque)
{
    assert(len <= NCSI_RESPONSE_CAPACITY);
    memcpy(opaque, buf, len);
    return len;
}

int main(int argc, char *argv[])
{
    SlirpConfig config = {};
    SlirpCb callbacks = {};
    Slirp *slirp = NULL;
    uint8_t ncsi_response[NCSI_RESPONSE_CAPACITY];

    config.version = SLIRP_CONFIG_VERSION_MAX;
    callbacks.send_packet = send_packet;
    slirp = slirp_new(&config, &callbacks, ncsi_response);

    test_ncsi_get_version_id(slirp);
    test_ncsi_oem_mlx_unsupported_command(slirp);

    slirp_cleanup(slirp);
}
