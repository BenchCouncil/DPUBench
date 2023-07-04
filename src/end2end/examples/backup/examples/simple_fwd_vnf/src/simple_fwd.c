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
#include <rte_random.h>
#include "doca_flow.h"
#include <doca_log.h>
#include "app_vnf.h"
#include "simple_fwd.h"
#include "simple_fwd_ft.h"
#include "simple_fwd_control.h"


DOCA_LOG_REGISTER(SIMPLE_FWD);

#define BE_IPV4_ADDR(a, b, c, d) \
	(RTE_BE32((a<<24) + (b<<16) + (c<<8) + d))
#define SET_MAC_ADDR(addr, a, b, c, d, e, f)\
do {\
	addr[0] = a & 0xff;\
	addr[1] = b & 0xff;\
	addr[2] = c & 0xff;\
	addr[3] = d & 0xff;\
	addr[4] = e & 0xff;\
	addr[5] = f & 0xff;\
} while (0)
#define BUILD_VNI(uint24_vni) (RTE_BE32(uint24_vni << 8))
#define METER_CIR 1250000
#define AGE_QUERY_BURST 128
#define DEF_RSS_QUEUE  1

static struct simple_fwd_app *simple_fwd_ins;
struct doca_flow_fwd *fwd_tbl_port[SIMPLE_FWD_PORTS];
struct doca_flow_fwd *sw_rss_fwd_tbl_port[SIMPLE_FWD_PORTS];
struct doca_flow_fwd *fwd_miss_tbl_port[SIMPLE_FWD_PORTS];

static void
simple_fwd_aged_flow_cb(struct simple_fwd_ft_user_ctx *ctx)
{
	struct simple_fwd_pipe_entry *entry =
		(struct simple_fwd_pipe_entry *)&ctx->data[0];

	if (entry->is_hw) {
		doca_flow_pipe_rm_entry(0, entry->hw_entry);
		entry->hw_entry = NULL;
	}
}

static int
simple_fwd_destroy_ins(void)
{
	uint16_t idx;

	if (simple_fwd_ins == NULL)
		return 0;
	/*the pipe entry will be free in port destroy.*/
	if (simple_fwd_ins->ft != NULL)
		free(simple_fwd_ins->ft);
	for (idx = 0; idx < simple_fwd_ins->nb_queues; idx++) {
		if (simple_fwd_ins->query_array[idx])
			free(simple_fwd_ins->query_array[idx]);
	}
	free(simple_fwd_ins);
	simple_fwd_ins = NULL;
	return 0;
}

static int
simple_fwd_create_ins(struct simple_fwd_port_cfg *port_cfg)
{
	uint16_t index;
	struct doca_flow_aged_query *entries;

	simple_fwd_ins = (struct simple_fwd_app *)malloc
		(sizeof(struct simple_fwd_app) +
		sizeof(struct doca_flow_aged_query) * port_cfg->nb_queues);
	if (simple_fwd_ins == NULL) {
		DOCA_LOG_CRIT("failed to allocate SF");
		goto fail_init;
	}
	memset(simple_fwd_ins, 0, sizeof(struct simple_fwd_app));
	simple_fwd_ins->ft = simple_fwd_ft_create(SIMPLE_FWD_MAX_FLOWS,
					sizeof(struct simple_fwd_pipe_entry),
					&simple_fwd_aged_flow_cb, NULL,
					port_cfg->age_thread);
	if (simple_fwd_ins->ft == NULL) {
		DOCA_LOG_CRIT("failed to allocate FT");
		goto fail_init;
	}
	simple_fwd_ins->nb_queues = port_cfg->nb_queues;
	for (index = 0 ; index < port_cfg->nb_queues; index++) {
		entries = malloc(sizeof(*entries) * AGE_QUERY_BURST);
		if (entries == NULL)
			goto fail_init;
		simple_fwd_ins->query_array[index] = entries;
	}

	return 0;
fail_init:
	simple_fwd_destroy_ins();
	return -1;
}

static struct doca_flow_fwd*
simple_fwd_build_port_fwd(struct simple_fwd_port_cfg *port_cfg)
{
	struct doca_flow_fwd *fwd = malloc(sizeof(struct doca_flow_fwd));

	memset(fwd, 0, sizeof(struct doca_flow_fwd));
	fwd->type = DOCA_FLOW_FWD_PORT;
	fwd->port_id = port_cfg->port_id;
	return fwd;
}

static struct doca_flow_fwd*
simple_fwd_build_rss_fwd(int n_queues)
{
	int i;
	struct doca_flow_fwd *fwd = malloc(sizeof(struct doca_flow_fwd));
	uint16_t *queues;

	memset(fwd, 0, sizeof(struct doca_flow_fwd));
	queues = malloc(sizeof(uint16_t) * n_queues);
	for (i = 1; i < n_queues; i++)
		queues[i - 1] = i;
	fwd->type = DOCA_FLOW_FWD_RSS;
	fwd->rss_queues = queues;
	fwd->rss_flags = DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_UDP;
	fwd->num_of_queues = n_queues - 1;
	fwd->rss_mark = 5;
	return fwd;
}


static struct doca_flow_fwd *
simple_fwd_build_port_fwd_miss(struct simple_fwd_port_cfg *port_cfg,
	struct doca_flow_port *port)
{
	struct doca_flow_fwd *fwd = malloc(sizeof(struct doca_flow_fwd));
	struct doca_flow_fwd *fwd_miss = malloc(sizeof(struct doca_flow_fwd));
	struct doca_flow_pipe *next_pipe = NULL;
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct doca_flow_actions actions = {0};
	struct doca_flow_match match = {0};
	struct doca_flow_error error = {0};
	struct doca_flow_monitor mon = {0};
	uint16_t *queues;
	int n_queues;
	int i;

	if (!fwd || !fwd_miss) {
		free(fwd);
		free(fwd_miss);
		return NULL;
	}

	memset(fwd, 0, sizeof(struct doca_flow_fwd));
	memset(fwd_miss, 0, sizeof(struct doca_flow_fwd));

	/* build match */
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = IPPROTO_UDP;

	/* build pipe cfg */
	pipe_cfg.port = port;
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;
	pipe_cfg.name = "NEXT_PIPE";

	/* build fwd config */
	n_queues = DEF_RSS_QUEUE;
	queues = malloc(sizeof(uint16_t) * n_queues);
	if (!queues) {
		free(fwd);
		free(fwd_miss);
		return NULL;
	}

	for (i = 0; i < n_queues; i++)
		queues[i] = 0;
	fwd->type = DOCA_FLOW_FWD_RSS;
	fwd->rss_queues = queues;
	fwd->rss_flags = DOCA_FLOW_RSS_IP | DOCA_FLOW_RSS_UDP;
	fwd->num_of_queues = n_queues;
	fwd->rss_mark = 6;

	/* build next_pipe */
	next_pipe = doca_flow_create_pipe(&pipe_cfg, fwd, NULL, &error);
	if (!next_pipe) {
		DOCA_DLOG_ERR("next pipe is null.");
		free(fwd_miss);
		return NULL;
	}

	/* build fwd_miss */
	fwd_miss->type = DOCA_FLOW_FWD_PIPE;
	fwd_miss->next_pipe = next_pipe;

	/* add fwd_miss entry if type is DOCA_FLOW_FWD_PIPE*/
	if (!doca_flow_pipe_add_entry(0, next_pipe, &match, &actions, &mon,
		fwd, &error))
		return NULL;

	return fwd_miss;
}

struct doca_flow_port*
simple_fwd_init_doca_port(struct simple_fwd_port_cfg *port_cfg)
{
#define MAX_PORT_STR (128)
	char port_id_str[MAX_PORT_STR];
	struct doca_flow_port_cfg doca_cfg_port;
	struct doca_flow_port *port;
	struct doca_flow_error error = {0};

	snprintf(port_id_str, MAX_PORT_STR, "%d", port_cfg->port_id);
	doca_cfg_port.type = DOCA_FLOW_PORT_DPDK_BY_ID;
	doca_cfg_port.devargs = port_id_str;
	doca_cfg_port.priv_data_size = sizeof(struct simple_fwd_port_cfg);

	if (port_cfg->port_id >= SIMPLE_FWD_PORTS) {
		DOCA_LOG_ERR("port id exceeds max ports id:%d",
			SIMPLE_FWD_PORTS);
		return NULL;
	}
	port = doca_flow_port_start(&doca_cfg_port, &error);
	if (port == NULL) {
		DOCA_LOG_ERR("failed to start port %s", error.message);
		return NULL;
	}

	*((struct simple_fwd_port_cfg *)doca_flow_port_priv_data(port)) =
		*port_cfg;
	sw_rss_fwd_tbl_port[port_cfg->port_id] =
	    simple_fwd_build_rss_fwd(port_cfg->nb_queues);

	fwd_tbl_port[port_cfg->port_id] = simple_fwd_build_port_fwd(port_cfg);
	fwd_miss_tbl_port[port_cfg->port_id] =
		simple_fwd_build_port_fwd_miss(port_cfg, port);
	return port;
}

static struct simple_fwd_port_cfg*
simple_fwd_get_port_cfg(struct doca_flow_port *port)
{
	return (struct simple_fwd_port_cfg *)
		doca_flow_port_priv_data(port);
}

static struct doca_flow_fwd*
simple_fwd_get_fwd(struct simple_fwd_port_cfg *port_cfg)
{
	uint16_t port_id = port_cfg->port_id;

	if (port_cfg->is_hairpin)
		return fwd_tbl_port[!port_id];
	else
		return sw_rss_fwd_tbl_port[port_id];
}

static struct doca_flow_fwd *
simple_fwd_get_fwd_miss(struct simple_fwd_port_cfg *port_cfg)
{
	uint16_t port_id = port_cfg->port_id;
	return fwd_miss_tbl_port[port_id];
}

static void
simple_fwd_build_eth_encap(struct doca_flow_encap_action *encap)
{
	/* build basic outer encap data, need fib to get the nexthop */
	SET_MAC_ADDR(encap->src_mac, 0xac, 0x3f, 0x56, 0x3d, 0x8a, 0x27);
	SET_MAC_ADDR(encap->dst_mac, 0x7c, 0xe2, 0xbd, 0x17, 0xa1, 0xc3);
	encap->src_ip.type = DOCA_FLOW_IP4_ADDR;
	encap->src_ip.ipv4_addr = BE_IPV4_ADDR(11, 12, 13, 14);
	encap->dst_ip.type = DOCA_FLOW_IP4_ADDR;
	encap->dst_ip.ipv4_addr = BE_IPV4_ADDR(21, 22, 23, 24);
}

static struct doca_flow_pipe*
simple_fwd_build_vxlan_pipe(struct doca_flow_port *port)
{
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct simple_fwd_port_cfg *port_cfg;
	struct doca_flow_monitor monitor = {0};
	struct doca_flow_actions actions = {0};
	struct doca_flow_match match = {0};
	struct doca_flow_error error = {0};
	struct doca_flow_fwd *fwd;
	struct doca_flow_fwd *fwd_miss;

	port_cfg = simple_fwd_get_port_cfg(port);

	/* build match part */
	match.out_dst_ip.ipv4_addr = UINT32_MAX;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_UDP;
	match.out_dst_port = RTE_BE16(DOCA_VXLAN_DEFAULT_PORT);
	match.tun.type = DOCA_FLOW_TUN_VXLAN;
	match.tun.vxlan_tun_id = UINT32_MAX;
	match.in_dst_ip.ipv4_addr = UINT32_MAX;
	match.in_src_ip.ipv4_addr = UINT32_MAX;
	match.in_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_l4_type = DOCA_PROTO_TCP;
	match.in_src_port = UINT16_MAX;
	match.in_dst_port = UINT16_MAX;

	/* build action part */
	actions.decap = true;
	actions.mod_dst_ip.ipv4_addr = UINT32_MAX;
	/* for vxlan pipe, do decap + modify + vxlan encap*/
	if (port_cfg->is_hairpin) {
		actions.has_encap = true;
		simple_fwd_build_eth_encap(&actions.encap);
		actions.encap.tun.type = DOCA_FLOW_TUN_VXLAN;
		actions.encap.tun.vxlan_tun_id = BUILD_VNI(0xcdab12);
	}
	/* build monitor part */
	monitor.flags = DOCA_FLOW_MONITOR_COUNT;
	monitor.flags |= DOCA_FLOW_MONITOR_METER;
	monitor.cir = METER_CIR;
	monitor.cbs = METER_CIR / 8;

	/* build fwd part */
	fwd = simple_fwd_get_fwd(port_cfg);
	fwd_miss = simple_fwd_get_fwd_miss(port_cfg);

	/* create pipe */
	pipe_cfg.name = "VXLAN_FWD";
	pipe_cfg.port = port;
	pipe_cfg.is_root = true;
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;
	pipe_cfg.monitor = &monitor;

	return doca_flow_create_pipe(&pipe_cfg, fwd, fwd_miss, &error);
}

static struct doca_flow_pipe*
simple_fwd_build_gre_pipe(struct doca_flow_port *port)
{
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct simple_fwd_port_cfg *port_cfg;
	struct doca_flow_actions actions = {0};
	struct doca_flow_match match = {0};
	struct doca_flow_error error = {0};

	port_cfg = simple_fwd_get_port_cfg(port);
	/* build match part */
	match.out_dst_ip.ipv4_addr = UINT32_MAX;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = IPPROTO_GRE;
	match.tun.type = DOCA_FLOW_TUN_GRE;
	match.tun.gre_key = UINT32_MAX;
	match.in_dst_ip.ipv4_addr = UINT32_MAX;
	match.in_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_src_ip.ipv4_addr = UINT32_MAX;
	match.in_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_l4_type = IPPROTO_TCP;
	match.in_src_port = UINT16_MAX;
	match.in_dst_port = UINT16_MAX;

	/* build action part */
	actions.decap = true;
	actions.mod_dst_ip.ipv4_addr = UINT32_MAX;
	/* for gre pipe, do decap + modify + vxlan encap*/
	if (port_cfg->is_hairpin) {
		actions.has_encap = true;
		simple_fwd_build_eth_encap(&actions.encap);
		actions.encap.tun.type = DOCA_FLOW_TUN_VXLAN;
		actions.encap.tun.vxlan_tun_id = BUILD_VNI(0xcdab12);
	}
	/* create pipe */
	pipe_cfg.name = "GRE_FWD";
	pipe_cfg.port = port;
	pipe_cfg.is_root = true;
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;

	return doca_flow_create_pipe(&pipe_cfg, NULL, NULL, &error);
}

static struct doca_flow_pipe*
simple_fwd_build_gtp_pipe(struct doca_flow_port *port)
{
	struct doca_flow_pipe_cfg pipe_cfg = {0};
	struct doca_flow_actions actions = {0};
	struct doca_flow_match match = {0};
	struct doca_flow_error error = {0};
	struct doca_flow_pipe *gtp_pipe;

	/* build match part */
	match.out_dst_ip.ipv4_addr = 0xffffffff;
	match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.out_l4_type = DOCA_PROTO_UDP;
	match.out_dst_port = DOCA_GTPU_PORT;
	match.tun.type = DOCA_FLOW_TUN_GTPU;
	match.tun.gtp_teid = 0xffffffff;
	match.in_dst_ip.ipv4_addr = 0xffffffff;
	match.in_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_src_ip.ipv4_addr = 0xffffffff;
	match.in_src_ip.type = DOCA_FLOW_IP4_ADDR;
	match.in_l4_type = IPPROTO_TCP;
	match.in_src_port = 0xffff;

	/* build action part */
	actions.decap = true;
	actions.mod_dst_ip.ipv4_addr = 0xffffffff;

	/* create pipe */
	pipe_cfg.name = "GTP_FWD";
	pipe_cfg.port = port;
	pipe_cfg.is_root = true;
	pipe_cfg.match = &match;
	pipe_cfg.actions = &actions;

	gtp_pipe = doca_flow_create_pipe(&pipe_cfg, NULL, NULL, &error);
	if (!gtp_pipe)
		DOCA_LOG_ERR("gtp pipe failed creation - %s (%u)", error.message, error.type);
	return gtp_pipe;
}

static int
simple_fwd_init_ports_and_pipes(struct simple_fwd_port_cfg *port_cfg)
{
	struct doca_flow_error error = {0};
	struct doca_flow_port *port;
	struct doca_flow_pipe *pipe;
	struct doca_flow_cfg cfg = {
		.total_sessions = SIMPLE_FWD_MAX_FLOWS,
		.queues = port_cfg->nb_queues,
		.is_hairpin = port_cfg->is_hairpin,
	};
	int index;

	if (doca_flow_init(&cfg, &error)) {
		DOCA_LOG_ERR("failed to init doca:%s", error.message);
		return -1;
	}
	/* build doca port */
	for (index = 0; index < SIMPLE_FWD_PORTS; index++) {
		port_cfg->port_id = index;
		port = simple_fwd_init_doca_port(port_cfg);
		if (port == NULL) {
			DOCA_LOG_ERR("failed to start port %d %s",
				index, error.message);
			return -1;
		}
		simple_fwd_ins->port[index] = port;
	}

	/* build pipe on each port */
	for (index = 0; index < SIMPLE_FWD_PORTS; index++) {
		port = simple_fwd_ins->port[index];

		/* build control pipe and entries*/
		pipe = simple_fwd_build_control_pipe(port);
		if (!pipe)
			return -1;
		if (simple_fwd_build_control_pipe_entry(pipe))
			return -1;
		simple_fwd_ins->pipe_control[index] = pipe;

		pipe = simple_fwd_build_gtp_pipe(port);
		if (pipe == NULL)
			return -1;
		simple_fwd_ins->pipe_gtp[index] = pipe;

		pipe = simple_fwd_build_gre_pipe(port);
		if (pipe == NULL)
			return -1;
		simple_fwd_ins->pipe_gre[index] = pipe;

		pipe = simple_fwd_build_vxlan_pipe(port);
		if (pipe == NULL)
			return -1;
		simple_fwd_ins->pipe_vxlan[index] = pipe;
	}
	return 0;
}

static int
simple_fwd_init(void *p)
{
	struct simple_fwd_port_cfg *port_cfg;
	int ret = 0;

	port_cfg = (struct simple_fwd_port_cfg *)p;
	ret = simple_fwd_create_ins(port_cfg);
	if (ret)
		return ret;
	return simple_fwd_init_ports_and_pipes(port_cfg);
}

static inline void
simple_fwd_match_set_tun(struct simple_fwd_pkt_info *pinfo,
			 struct doca_flow_match *match)
{
	if (!pinfo->tun_type)
		return;
	match->tun.type = pinfo->tun_type;
	switch (match->tun.type) {
	case DOCA_FLOW_TUN_VXLAN:
		match->tun.vxlan_tun_id = pinfo->tun.vni;
		break;
	case DOCA_FLOW_TUN_GRE:
		match->tun.gre_key = pinfo->tun.gre_key;
		break;
	case DOCA_FLOW_TUN_GTPU:
		match->tun.gtp_teid = pinfo->tun.teid;
		break;
	default:
		DOCA_LOG_WARN("unsupport tun type:%u", match->tun.type);
		break;
	}
}

void
simple_fwd_build_entry_match(struct simple_fwd_pkt_info *pinfo,
			     struct doca_flow_match *match)
{
	memset(match, 0x0, sizeof(*match));
	/* set match all fields, pipe will select which field to match */
	memcpy(match->out_dst_mac, simple_fwd_pinfo_outer_mac_dst(pinfo),
		DOCA_ETHER_ADDR_LEN);
	memcpy(match->out_src_mac, simple_fwd_pinfo_outer_mac_src(pinfo),
		DOCA_ETHER_ADDR_LEN);
	match->out_dst_ip.ipv4_addr = simple_fwd_pinfo_outer_ipv4_dst(pinfo);
	match->out_src_ip.ipv4_addr = simple_fwd_pinfo_outer_ipv4_src(pinfo);
	match->out_src_port = simple_fwd_pinfo_outer_src_port(pinfo);
	match->out_dst_port = simple_fwd_pinfo_outer_dst_port(pinfo);
	match->out_l4_type = pinfo->outer.l4_type;
	if (!pinfo->tun_type)
		return;
	simple_fwd_match_set_tun(pinfo, match);
	match->in_dst_ip.ipv4_addr = simple_fwd_pinfo_inner_ipv4_dst(pinfo);
	match->in_src_ip.ipv4_addr = simple_fwd_pinfo_inner_ipv4_src(pinfo);
	match->in_l4_type = pinfo->inner.l4_type;
	match->in_src_port = simple_fwd_pinfo_inner_src_port(pinfo);
	match->in_dst_port = simple_fwd_pinfo_inner_dst_port(pinfo);
}

void
simple_fwd_build_entry_action(struct simple_fwd_pkt_info *pinfo,
			      struct doca_flow_actions *action)
{
	/* include all modify action cases*/
	SET_MAC_ADDR(action->mod_dst_mac, 0x0c, 0x42, 0xa1, 0x4b, 0xc5, 0x8c);
	action->mod_dst_ip.ipv4_addr = BE_IPV4_ADDR(18, 18, 18, 18);
	action->mod_dst_port = RTE_BE16(55555);

	/* set vxlan encap data, pipe will decide if do encap */
	action->has_encap = true;
	/*
	 * we have a basic encap data when create pipe, there we do
	 * some modify to test the modify encap and decap.
	 */
	memset(action->encap.src_mac, 0xaa, sizeof(action->encap.src_mac));
	memset(action->encap.dst_mac, 0xbb, sizeof(action->encap.src_mac));
	action->encap.src_ip.type = DOCA_FLOW_IP4_ADDR;
	action->encap.src_ip.ipv4_addr = BE_IPV4_ADDR(172, 18, 21, 22);
	action->encap.dst_ip.type = DOCA_FLOW_IP4_ADDR;
	action->encap.dst_ip.ipv4_addr = BE_IPV4_ADDR(155, 27, 12, 38);
	/*both vxlan/gre after decap will do vxlan encap.*/
	action->encap.tun.type = DOCA_FLOW_TUN_VXLAN;
	action->encap.tun.vxlan_tun_id = BUILD_VNI(0xadadad);
}

/* build monitor on each entry*/
void
simple_fwd_build_entry_monitor(struct simple_fwd_pkt_info *pinfo,
			       struct doca_flow_monitor *monitor,
			       void *user_ctx)
{
	monitor->flags = DOCA_FLOW_MONITOR_COUNT;
	/* meter policy is only created on vxlan pipe*/
	if (pinfo->tun_type == DOCA_FLOW_TUN_VXLAN) {
		monitor->flags |= DOCA_FLOW_MONITOR_METER;
		monitor->cir = METER_CIR;
		monitor->cbs = METER_CIR / 8;
	}
	monitor->flags |= DOCA_FLOW_MONITOR_AGING;
	/* flows will be aged out in 5 - 60s */
	monitor->aging = (uint32_t)rte_rand() % 55 + 5;
	monitor->user_data = (uint64_t)user_ctx;
}

static struct doca_flow_pipe*
simple_fwd_select_pipe(struct simple_fwd_pkt_info *pinfo)
{
	if (pinfo->tun_type == DOCA_FLOW_TUN_GRE)
		return simple_fwd_ins->pipe_gre[pinfo->orig_port_id];
	if (pinfo->tun_type == DOCA_FLOW_TUN_VXLAN)
		return simple_fwd_ins->pipe_vxlan[pinfo->orig_port_id];
	if (pinfo->tun_type == DOCA_FLOW_TUN_GTPU)
		return simple_fwd_ins->pipe_gtp[pinfo->orig_port_id];
	return NULL;
}

static struct doca_flow_fwd*
simple_fwd_select_fwd(struct simple_fwd_pkt_info *pinfo)
{
	struct doca_flow_port *port;
	struct simple_fwd_port_cfg *port_cfg;

	/*
	 * for vxlan case, test fwd is defined in pipe, for
	 * other cases, test fwd is defined in each entry.
	 */
	if (pinfo->tun_type == DOCA_FLOW_TUN_VXLAN)
		return NULL;

	port = simple_fwd_ins->port[pinfo->orig_port_id];
	port_cfg = simple_fwd_get_port_cfg(port);
	return simple_fwd_get_fwd(port_cfg);
}

struct doca_flow_pipe_entry*
simple_fwd_pipe_add_entry(struct simple_fwd_pkt_info *pinfo,
			  void *user_ctx)
{
	struct doca_flow_match match;
	struct doca_flow_monitor monitor = {0};
	struct doca_flow_actions action = {0};
	struct doca_flow_error error = {0};
	struct doca_flow_pipe *pipe;
	struct doca_flow_fwd *fwd = NULL;
	struct doca_flow_pipe_entry *entry;

	pipe = simple_fwd_select_pipe(pinfo);
	if (pipe == NULL) {
		DOCA_LOG_WARN("failed to select pipe on this packet");
		return NULL;
	}
	fwd = simple_fwd_select_fwd(pinfo);
	simple_fwd_build_entry_match(pinfo, &match);
	simple_fwd_build_entry_action(pinfo, &action);
	simple_fwd_build_entry_monitor(pinfo, &monitor, user_ctx);
	entry = doca_flow_pipe_add_entry(pinfo->pipe_queue,
		pipe, &match, &action, &monitor, fwd, &error);
	if (!entry)
		DOCA_LOG_ERR("failed adding entry to pipe: error=%s, type=%u",
			     error.message, error.type);
	return entry;
}

/*
 * currently we only can get the ft_entry ctx, but for the aging,
 * we need get the ft_entry pointer, add destroy the ft entry.
 */
#define GET_FT_ENTRY(ctx) \
	container_of(ctx, struct simple_fwd_ft_entry, user_ctx)
static int
simple_fwd_handle_new_flow(struct simple_fwd_pkt_info *pinfo,
			   struct simple_fwd_ft_user_ctx **ctx)
{
	struct simple_fwd_pipe_entry *entry = NULL;
	struct simple_fwd_ft_entry *ft_entry;

	if (!simple_fwd_ft_add_new(simple_fwd_ins->ft, pinfo, ctx)) {
		DOCA_LOG_DBG("failed create new entry");
		return -1;
	}
	entry = (struct simple_fwd_pipe_entry *)&(*ctx)->data[0];
	entry->hw_entry = simple_fwd_pipe_add_entry(pinfo, (void *)(*ctx));
	if (entry->hw_entry == NULL) {
		ft_entry = GET_FT_ENTRY(*ctx);
		simple_fwd_ft_destroy_entry(simple_fwd_ins->ft, ft_entry);
		return -1;
	}
	entry->is_hw = true;

	return 0;
}

static bool
simple_fwd_need_new_ft(struct simple_fwd_pkt_info *pinfo)
{
	if (pinfo->outer.l3_type != IPV4) {
		DOCA_LOG_WARN("outer.l3_type %u not supported",
			pinfo->outer.l3_type);
		return false;
	}
	if ((pinfo->outer.l4_type != DOCA_PROTO_TCP) &&
		(pinfo->outer.l4_type != DOCA_PROTO_UDP) &&
		(pinfo->outer.l4_type != DOCA_PROTO_GRE)) {
		DOCA_LOG_WARN("outer.l4_type %u not supported",
			pinfo->outer.l4_type);
		return false;
	}
	return true;
}

static int
simple_fwd_handle_packet(struct simple_fwd_pkt_info *pinfo)
{
	struct simple_fwd_ft_user_ctx *ctx = NULL;
	struct simple_fwd_pipe_entry *entry = NULL;

	if (!simple_fwd_need_new_ft(pinfo))
		return -1;
	if (!simple_fwd_ft_find(simple_fwd_ins->ft, pinfo, &ctx)) {
		if (simple_fwd_handle_new_flow(pinfo, &ctx))
			return -1;
	}
	entry = (struct simple_fwd_pipe_entry *)&ctx->data[0];
	entry->total_pkts++;
	return 0;
}

/*
 * currently, the handle aging only on main core, we need implement
 * the pipe with per-queue, so the offload can work on each queue,
 * also the aging can work on each queue.
 * will remove this comment after it's be completed.
 */
static void
simple_fwd_handle_aging(uint16_t queue)
{
#define MAX_HANDLING_TIME_MS 10	/*ms*/
	struct doca_flow_aged_query *entries;
	struct simple_fwd_ft_entry *ft_entry;
	int idex, ret;

	if (queue > simple_fwd_ins->nb_queues)
		return;
	entries = simple_fwd_ins->query_array[queue];
	ret = doca_flow_handle_aging(queue, MAX_HANDLING_TIME_MS,
		entries, AGE_QUERY_BURST);
	for (idex = 0; idex < ret; idex++) {
		ft_entry = GET_FT_ENTRY((void *)entries[idex].user_data);
		simple_fwd_ft_destroy_entry(simple_fwd_ins->ft, ft_entry);
	}
}

static int
simple_fwd_destroy(void)
{
	doca_flow_destroy();
	simple_fwd_destroy_ins();
	return 0;
}

struct app_vnf simple_fwd_vnf = {
	.vnf_init = &simple_fwd_init,
	.vnf_process_pkt = &simple_fwd_handle_packet,
	.vnf_destroy = &simple_fwd_destroy,
	.vnf_flow_age = &simple_fwd_handle_aging,
};

struct app_vnf*
simple_fwd_get_vnf(void)
{
	return &simple_fwd_vnf;
}
