/*
 * Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "doca_flow.h"
#include <doca_log.h>
#include "app_vnf.h"
#include <sys/types.h>
#include <rte_mbuf.h>
#include "simple_fwd.h"


DOCA_LOG_REGISTER(SIMPLE_FWD);

uint16_t c_queues[1];
struct doca_flow_fwd c_fwd;
struct doca_flow_pipe *c_pipe[SIMPLE_FWD_PORTS];

static struct doca_flow_fwd *
simple_fwd_build_control_fwd()
{
	memset(&c_fwd, 0, sizeof(struct doca_flow_fwd));
	c_queues[0] = 0;
	c_fwd.type = DOCA_FLOW_FWD_RSS;
	c_fwd.rss_queues = c_queues;
	c_fwd.rss_flags = DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_UDP;
	c_fwd.num_of_queues = 1;
	c_fwd.rss_mark = 0;
	return &c_fwd;
}

static int
simple_fwd_build_vxlan_control(struct doca_flow_pipe *c_pipe)
{
	struct doca_flow_match match = {0};
	struct doca_flow_error error = {0};
	struct doca_flow_fwd *fwd = NULL;
	uint8_t pri;

	/* build match part */
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = IPPROTO_UDP;
	match.out_dst_port = rte_cpu_to_be_16(DOCA_VXLAN_DEFAULT_PORT);
	match.tun.type = DOCA_FLOW_TUN_VXLAN;
	match.in_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_l4_type = IPPROTO_TCP;

	/* build fwd part */
	fwd = simple_fwd_build_control_fwd();
	pri = 1;
	if (!doca_flow_control_pipe_add_entry(0, pri, c_pipe, &match, NULL,
			fwd, &error))
		return -1;

	return 0;
}

static int
simple_fwd_build_gre_control(struct doca_flow_pipe *c_pipe)
{
	struct doca_flow_match match = {0};
	struct doca_flow_error error = {0};
	struct doca_flow_fwd *fwd = NULL;
	uint8_t pri;

	/* build match part */
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = IPPROTO_GRE;
	match.tun.type = DOCA_FLOW_TUN_GRE;
	match.in_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_l4_type = IPPROTO_TCP;

	/* build fwd part */
	fwd = simple_fwd_build_control_fwd();
	pri = 1;
	if (!doca_flow_control_pipe_add_entry(0, pri, c_pipe, &match, NULL,
			fwd, &error))
		return -1;
	return 0;
}

int
simple_fwd_build_control_pipe_entry(struct doca_flow_pipe *c_pipe)
{
	if (!c_pipe)
		return -1;

	if (simple_fwd_build_vxlan_control(c_pipe))
		return -1;
	if (simple_fwd_build_gre_control(c_pipe))
		return -1;
	return 0;
}

struct doca_flow_pipe *
simple_fwd_build_control_pipe(struct doca_flow_port *port)
{
	struct doca_flow_error error;

	return doca_flow_create_control_pipe(port, &error);
}


