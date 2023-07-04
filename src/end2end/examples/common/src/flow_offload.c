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

#include <rte_sft.h>

#include "flow_offload.h"
#include "utils.h"

DOCA_LOG_REGISTER(FOFLD);

#define SFT_ZONE 0xcafe
#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024
#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

#define MAX_PATTERN_NUM 5
#define MAX_ACTION_NUM 4
#define GROUP_POST_SFT 1001

enum POST_SFT_GROUP_PRIORITY {
	SET_STATE_PRIORITY,
	SFT_TO_RSS_PRIORITY,
};

enum PRE_SFT_GROUP_PRIORITY {
	JUMP_TO_SFT_PRIORITY = 0,
	HAIRPIN_NON_L4_PRIORITY = 3,
};

static struct rte_flow *set_jump_to_sft_action[8];
static struct rte_flow *query_hairpin[4];
static struct rte_flow *rss_non_state[2];
static struct rte_flow *hair_non_l4[2];

static struct rte_flow *
set_forward_fid_with_state(uint16_t port_id, struct rte_flow_action_rss *action_rss,
	uint8_t sft_state, struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow_item_sft sft_spec_and_mask = { .fid_valid = 1,
						       .state = sft_state };
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.priority = SET_STATE_PRIORITY;
	attr.group = GROUP_POST_SFT;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	if (sft_state == HAIRPIN_MATCHED_FLOW) {
		action[1].type = RTE_FLOW_ACTION_TYPE_RSS;
		action[1].conf = action_rss;
	} else if (sft_state == DROP_FLOW)
		action[1].type = RTE_FLOW_ACTION_TYPE_DROP;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_SFT;
	pattern[0].mask = &sft_spec_and_mask;
	pattern[0].spec = &sft_spec_and_mask;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	ret = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (ret == 0)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

static struct rte_flow *
set_rss_non_state_traffic(uint16_t port_id, struct rte_flow_action_rss *action_rss,
	struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.priority = SFT_TO_RSS_PRIORITY;
	attr.group = GROUP_POST_SFT;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_RSS;
	action[1].conf = action_rss;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	ret = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (ret == 0)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

static struct rte_flow *
set_forward_l4_to_sft_action(uint8_t port_id, uint8_t l3_protocol, uint8_t l4_protocol,
	struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow_action_sft action_sft = { .zone = SFT_ZONE };
	struct rte_flow_action_jump action_jump = { .group = GROUP_POST_SFT };
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.group = 0;
	attr.priority = JUMP_TO_SFT_PRIORITY;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_SFT;
	action[1].conf = &action_sft;
	action[2].type = RTE_FLOW_ACTION_TYPE_JUMP;
	action[2].conf = &action_jump;
	action[3].type = RTE_FLOW_ACTION_TYPE_END;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	if (l3_protocol != IPPROTO_IPV6)
		pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	else
		pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV6;
	if (l4_protocol == IPPROTO_UDP)
		pattern[2].type = RTE_FLOW_ITEM_TYPE_UDP;
	else
		pattern[2].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[3].type = RTE_FLOW_ACTION_TYPE_END;

	ret = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (ret == 0)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}

static struct rte_flow *
set_hairpin_non_l4_packets(uint16_t port_id, struct rte_flow_action_rss *action_rss,
	struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow *flow = NULL;

	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	attr.group = 0;
	attr.priority = HAIRPIN_NON_L4_PRIORITY;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[1].type = RTE_FLOW_ACTION_TYPE_RSS;
	action[1].conf = action_rss;
	action[2].type = RTE_FLOW_ACTION_TYPE_END;

	memset(pattern, 0, sizeof(pattern));
	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

	ret = rte_flow_validate(port_id, &attr, pattern, action, error);
	if (ret == 0)
		flow = rte_flow_create(port_id, &attr, pattern, action, error);
	return flow;
}


static int
bind_hairpin_queues(uint16_t port_id)
{
	/* Configure the Rx and Tx hairpin queues for the selected port. */
	int ret, peer_port, peer_ports_len;
	uint16_t peer_ports[RTE_MAX_ETHPORTS];

	/* bind current Tx to all peer Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, RTE_MAX_ETHPORTS, 1);
	if (peer_ports_len < 0)
		return peer_ports_len;
	for (peer_port = 0; peer_port < peer_ports_len; peer_port++) {
		ret = rte_eth_hairpin_bind(port_id, peer_ports[peer_port]);
		if (ret < 0)
			return ret;
	}
	/* bind all peer Tx to current Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, RTE_MAX_ETHPORTS, 0);
	if (peer_ports_len < 0)
		return peer_ports_len;
	for (peer_port = 0; peer_port < peer_ports_len; peer_port++) {
		ret = rte_eth_hairpin_bind(peer_ports[peer_port], port_id);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int
unbind_hairpin_queues(uint16_t port_id)
{
	/* Configure the Rx and Tx hairpin queues for the selected port. */
	int ret, peer_port, peer_ports_len;
	uint16_t peer_ports[RTE_MAX_ETHPORTS];

	/* unbind current Tx from all peer Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, RTE_MAX_ETHPORTS, 1);
	if (peer_ports_len < 0)
		return peer_ports_len;
	for (peer_port = 0; peer_port < peer_ports_len; peer_port++) {
		ret = rte_eth_hairpin_unbind(port_id, peer_ports[peer_port]);
		if (ret < 0)
			return ret;
	}
	/* unbind all peer Tx from current Rx */
	peer_ports_len = rte_eth_hairpin_get_peer_ports(port_id, peer_ports, RTE_MAX_ETHPORTS, 0);
	if (peer_ports_len < 0)
		return peer_ports_len;
	for (peer_port = 0; peer_port < peer_ports_len; peer_port++) {
		ret = rte_eth_hairpin_unbind(peer_ports[peer_port], port_id);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int
setup_hairpin_queues(uint16_t port_id, uint16_t peer_port_id, uint16_t *reserved_hairpin_q_list,
	int hairpin_queue_len)
{
	/* Port:
	 *	0. RX queue
	 *	1. RX hairpin queue rte_eth_rx_hairpin_queue_setup
	 *	2. TX hairpin queue rte_eth_tx_hairpin_queue_setup
	 */

	int ret, hairpin_q;
	uint16_t nb_tx_rx_desc = 2048;
	uint32_t manual = 1;
	uint32_t tx_exp = 1;
	struct rte_eth_hairpin_conf hairpin_conf = { .peer_count = 1,
						     .manual_bind = !!manual,
						     .tx_explicit = !!tx_exp,
						     .peers[0] = { peer_port_id }, };

	for (hairpin_q = 0; hairpin_q < hairpin_queue_len; hairpin_q++) {
		//TX
		hairpin_conf.peers[0].queue = reserved_hairpin_q_list[hairpin_q];
		ret = rte_eth_tx_hairpin_queue_setup(port_id, reserved_hairpin_q_list[hairpin_q],
					nb_tx_rx_desc, &hairpin_conf);
		if (ret != 0)
			return ret;
		//RX
		hairpin_conf.peers[0].queue = reserved_hairpin_q_list[hairpin_q];
		ret = rte_eth_rx_hairpin_queue_setup(port_id, reserved_hairpin_q_list[hairpin_q],
					nb_tx_rx_desc, &hairpin_conf);
		if (ret != 0)
			return ret;
	}
	return 0;
}

static void
enable_hairpin_queues(uint8_t nb_ports)
{
	uint8_t port_id;

	for (port_id = 0; port_id < nb_ports; port_id++)
		if (bind_hairpin_queues(port_id) != 0)
			APP_EXIT("Hairpin bind failed on port=%u", port_id);

}

void
dpdk_sft_init(const struct application_dpdk_config *app_dpdk_config)
{
	int ret = 0;
	uint8_t port_id = 0;
	uint8_t queue_index;
	uint8_t nb_ports = app_dpdk_config->port_config.nb_ports;
	uint8_t nb_queues = app_dpdk_config->port_config.nb_queues;
	uint8_t nb_hairpin_q = app_dpdk_config->port_config.nb_hairpin_q;
	uint16_t queue_list[nb_queues];
	uint16_t hairpin_queue_list[nb_hairpin_q];
	struct rte_sft_conf sft_config = {
		.nb_queues = nb_queues,
		.nb_max_entries = 1 << 20, /* This is max number of connections */
		.tcp_ct_enable = app_dpdk_config->sft_config.enable_ct,
		.ipfrag_enable = 1,
		.reorder_enable = 1,
		.default_aging = 60,
		.nb_max_ipfrag = 4096,
		.app_data_len = 1,
	};
	struct rte_flow_action_rss action_rss;
	struct rte_flow_action_rss action_rss_hairpin;
	struct rte_sft_error sft_error;
	struct rte_flow_error rte_error;
	uint8_t rss_key[40];
	struct rte_eth_rss_conf rss_conf = {
		.rss_key = rss_key,
		.rss_key_len = 40,
	};

	ret = rte_sft_init(&sft_config, &sft_error);
	if (ret < 0)
		APP_EXIT("SFT init failed");

	ret = rte_eth_dev_rss_hash_conf_get(port_id, &rss_conf);
	if (ret != 0)
		APP_EXIT("Get port RSS configuration failed, ret=%d", ret);

	for (queue_index = 0; queue_index < nb_queues; queue_index++)
		queue_list[queue_index] = queue_index;
	action_rss.queue_num = nb_queues;
	action_rss.queue = queue_list;
	action_rss.types = rss_conf.rss_hf;
	action_rss.key_len = rss_conf.rss_key_len;
	action_rss.key = rss_conf.rss_key;
	action_rss.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	action_rss.level = 0;

	/* Hairpin queues are indexed right after regular queues */
	for (queue_index = 0; queue_index < nb_hairpin_q; queue_index++)
		hairpin_queue_list[queue_index] = nb_queues + queue_index;
	action_rss_hairpin.queue_num = nb_hairpin_q;
	action_rss_hairpin.queue = hairpin_queue_list;
	action_rss_hairpin.types = rss_conf.rss_hf;
	action_rss_hairpin.key_len = rss_conf.rss_key_len;
	action_rss_hairpin.key = rss_conf.rss_key;
	action_rss_hairpin.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	action_rss_hairpin.level = 0;

	/*
	 * RTE_FLOW rules are created as list:
	 * 1. Hairpin all non L4 traffic with the lowest priority in group 0
	 * 2. Forward IPv4/6 L4 traffic to SFT with predefined zone in group 0
	 * 3. Check traffic for state && valid fid for either hairpinned or dropped state in the SFT group
	 * 4. RSS all the L4 non-state traffic to the ARM cores
	 */

	for (port_id = 0; port_id < nb_ports; port_id++) {
		set_jump_to_sft_action[port_id] =
			set_forward_l4_to_sft_action(port_id, IPPROTO_IP, IPPROTO_UDP, &rte_error);
		if (set_jump_to_sft_action[port_id] == NULL)
			APP_EXIT("Forward to SFT IPV4-UDP failed, error=%s", rte_error.message);

		set_jump_to_sft_action[port_id + 2] =
			set_forward_l4_to_sft_action(port_id, IPPROTO_IP, IPPROTO_TCP, &rte_error);
		if (set_jump_to_sft_action[port_id + 2] == NULL)
			APP_EXIT("Forward to SFT IPV4-TCP failed, error=%s", rte_error.message);
		set_jump_to_sft_action[port_id + 4] =
			set_forward_l4_to_sft_action(port_id, IPPROTO_IPV6,
				IPPROTO_UDP, &rte_error);
		if (set_jump_to_sft_action[port_id + 4] == NULL)
			APP_EXIT("Forward to SFT IPV6-UDP failed, error=%s", rte_error.message);
		set_jump_to_sft_action[port_id + 6] =
			set_forward_l4_to_sft_action(port_id, IPPROTO_IPV6,
				IPPROTO_TCP,  &rte_error);
		if (set_jump_to_sft_action[port_id + 6] == NULL)
			APP_EXIT("Forward to SFT IPV6-TCP failed, error=%s", rte_error.message);

		rss_non_state[port_id] =
			set_rss_non_state_traffic(port_id, &action_rss, &rte_error);
		if (rss_non_state[port_id] == NULL)
			APP_EXIT("SFT set non state RSS failed, error=%s", rte_error.message);

		if (app_dpdk_config->sft_config.enable_state_hairpin) {
			query_hairpin[port_id] =
				set_forward_fid_with_state(port_id, &action_rss_hairpin,
					HAIRPIN_MATCHED_FLOW, &rte_error);
			if (query_hairpin[port_id] == NULL)
				APP_EXIT("Forward fid with state, error=%s", rte_error.message);
		}
		if (app_dpdk_config->sft_config.enable_state_drop) {
			query_hairpin[port_id + 2] =
				set_forward_fid_with_state(port_id, &action_rss_hairpin,
					DROP_FLOW, &rte_error);
			if (query_hairpin[port_id + 2] == NULL)
				APP_EXIT("Drop fid with state, error=%s", rte_error.message);
		}
		hair_non_l4[port_id] =
			set_hairpin_non_l4_packets(port_id, &action_rss_hairpin, &rte_error);
		if (hair_non_l4[port_id] == NULL)
			APP_EXIT("Hairpin flow creation failed: %s", rte_error.message);
	}
}

static struct rte_mempool *
allocate_mempool(uint8_t nb_ports, int nb_queues)
{
	struct rte_mempool *mbuf_pool;
	/* Creates a new mempool in memory to hold the mbufs */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports * nb_queues,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL)
		APP_EXIT("Cannot allocate mbuf pool");
	return mbuf_pool;
}

static int
port_init(struct rte_mempool *mbuf_pool, uint8_t port, const uint8_t nb_queues,
	int nb_hairpin_queues)
{
	int ret;
	int symmetric_hash_key_length = 40;
	const uint16_t rx_rings = nb_queues;
	const uint16_t tx_rings = nb_queues;
	uint16_t q, queue_index;
	uint16_t rss_queue_list[nb_hairpin_queues];
	struct rte_ether_addr addr;
	struct rte_eth_dev_info dev_info;
	uint8_t symmetric_hash_key[40] = {
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, };
	const struct rte_eth_conf port_conf_default = {
		.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN, },
		.rx_adv_conf = {
			.rss_conf = {
				.rss_key_len = symmetric_hash_key_length,
				.rss_key = symmetric_hash_key,
				.rss_hf = ETH_RSS_PROTO_MASK,
			},
		},
	};
	struct rte_eth_conf port_conf = port_conf_default;

	if (!rte_eth_dev_is_valid_port(port))
		APP_EXIT("Invalid port");
	ret = rte_eth_dev_info_get(port, &dev_info);
	if (ret != 0)
		APP_EXIT("Failed getting device (port %u) info, error=%s", port, strerror(-ret));
	port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;
	/* Configure the Ethernet device */
	ret = rte_eth_dev_configure(port, rx_rings + nb_hairpin_queues,
					  tx_rings + nb_hairpin_queues, &port_conf);
	if (ret != 0)
		return ret;
	if (port_conf_default.rx_adv_conf.rss_conf.rss_hf !=
		port_conf.rx_adv_conf.rss_conf.rss_hf) {
		DOCA_LOG_DBG("Port %u modified RSS hash function based on hardware support, requested:%#"PRIx64" configured:%#"PRIx64"",
			port,
			port_conf_default.rx_adv_conf.rss_conf.rss_hf,
			port_conf.rx_adv_conf.rss_conf.rss_hf);
	}
	/* Enable RX in promiscuous mode for the Ethernet device */
	ret = rte_eth_promiscuous_enable(port);
	if (ret != 0)
		return ret;

	/* Allocate and set up RX queues according to number of cores per Ethernet port */
	for (q = 0; q < rx_rings; q++) {
		ret = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (ret < 0)
			return ret;
	}
	/* Allocate and set up TX queues according to number of cores per Ethernet port */
	for (q = 0; q < tx_rings; q++) {
		ret = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
		if (ret < 0)
			return ret;
	}
	/* Enabled hairpin queue before port start */
	if (nb_hairpin_queues) {
		for (queue_index = 0; queue_index < nb_hairpin_queues; queue_index++)
			rss_queue_list[queue_index] = nb_queues + queue_index;
		ret = setup_hairpin_queues(port, port ^ 1, rss_queue_list, nb_hairpin_queues);
		if (ret != 0)
			APP_EXIT("Cannot hairpin port %"PRIu8 ", ret=%d", port, ret);
	}

	/* Start the Ethernet port */
	ret = rte_eth_dev_start(port);
	if (ret < 0)
		return ret;
	/* Display the port MAC address */
	rte_eth_macaddr_get(port, &addr);
	DOCA_LOG_DBG("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
		" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "",
		(unsigned int)port,
		addr.addr_bytes[0], addr.addr_bytes[1],
		addr.addr_bytes[2], addr.addr_bytes[3],
		addr.addr_bytes[4], addr.addr_bytes[5]);
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port) > 0 &&
	    rte_eth_dev_socket_id(port) != (int)rte_socket_id()) {
		DOCA_LOG_WARN("Port %u is on remote NUMA node to polling thread", port);
		DOCA_LOG_WARN("\tPerformance will not be optimal.");
	}
	return 0;
}

int
dpdk_ports_init(struct application_port_config *port_config)
{
	int ret;
	uint8_t port_id;
	uint8_t nb_ports = port_config->nb_ports;
	uint8_t nb_queues = port_config->nb_queues;
	uint8_t nb_hairpin_q = port_config->nb_hairpin_q;
	struct rte_mempool *mbuf_pool;

	/* Initialize mbuf */
	mbuf_pool = allocate_mempool(nb_ports, nb_queues);

	/* Needed by SFT to mark packets */
	ret = rte_flow_dynf_metadata_register();
	if (ret < 0)
		APP_EXIT("Metadata register failed");

	for (port_id = 0; port_id < nb_ports; port_id++)
		if (port_init(mbuf_pool, port_id, nb_queues, nb_hairpin_q) != 0)
			APP_EXIT("Cannot init port %"PRIu8, port_id);
	return 0;
}

void
flow_offload_query_counters(void)
{
	int flow_i;
	struct rte_flow_action action[] = {
		[0] = { .type = RTE_FLOW_ACTION_TYPE_COUNT },
		[1] = { .type = RTE_FLOW_ACTION_TYPE_END },
	};
	struct rte_flow_query_count count = {0};
	struct rte_flow_error rte_error;
	uint64_t total_ingress = 0;
	uint64_t total_rss = 0;
	uint64_t total_dropped = 0;
	uint64_t total_egress = 0;
	uint64_t total_ingress_non_l4 = 0;

	DOCA_LOG_DBG("------------ L4 Jump to SFT----------------");
	for (flow_i = 0; flow_i < 4; flow_i++) {
		if (rte_flow_query(flow_i % 2, set_jump_to_sft_action[flow_i], &action[0], &count,
					&rte_error) != 0) {
			DOCA_LOG_ERR("query failed, error=%s", rte_error.message);
		} else {

			if (flow_i < 2)
				DOCA_LOG_DBG("Port %d UDP - %lu", flow_i % 2, count.hits);
			else
				DOCA_LOG_DBG("Port %d TCP - %lu", flow_i % 2, count.hits);
			total_ingress += count.hits;
		}
	}

	DOCA_LOG_DBG("------------ IPV6 L4 Jump to SFT----------------");
	for (flow_i = 4; flow_i < 8; flow_i++) {
		if (rte_flow_query(flow_i % 2, set_jump_to_sft_action[flow_i], &action[0], &count,
					&rte_error) != 0) {
			DOCA_LOG_ERR("query failed, error=%s", rte_error.message);
		} else {

			if (flow_i < 2)
				DOCA_LOG_DBG("Port %d IPV6 UDP - %lu", flow_i % 2, count.hits);
			else
				DOCA_LOG_DBG("Port %d IPV6 TCP - %lu", flow_i % 2, count.hits);
			total_ingress += count.hits;
		}
	}

	DOCA_LOG_DBG("----------Hairpin non L4 traffic-----------");
	for (flow_i = 0; flow_i < 2; flow_i++) {
		if (rte_flow_query(flow_i % 2, hair_non_l4[0], &action[0], &count,
					&rte_error) != 0) {
			DOCA_LOG_ERR("query failed, error=%s", rte_error.message);
		} else {
			DOCA_LOG_DBG("Port %d non L4- %lu", flow_i % 2, count.hits);
			total_ingress += count.hits;
		}
	}

	DOCA_LOG_DBG("---------Hairpin using state post SFT -----");
	for (flow_i = 0; flow_i < 4; flow_i++) {
		if (rte_flow_query(flow_i % 2, query_hairpin[flow_i], &action[0], &count,
					&rte_error) != 0) {
			DOCA_LOG_ERR("query failed, error=%s", rte_error.message);
		} else {

			if (flow_i < 2) {
				DOCA_LOG_DBG("Port %d state hairpin - %lu", flow_i % 2, count.hits);
				total_egress += count.hits;
			} else {
				DOCA_LOG_DBG("Port %d state drop - %lu", flow_i % 2, count.hits);
				total_dropped += count.hits;
			}
		}
	}

	DOCA_LOG_DBG("---------------RSS post SFT----------------");
	for (flow_i = 0; flow_i < 2; flow_i++) {
		if (rte_flow_query(flow_i % 2, rss_non_state[flow_i], &action[0], &count,
					&rte_error) != 0) {
			DOCA_LOG_ERR("query failed, error=%s", rte_error.message);
		} else {
			DOCA_LOG_DBG("Port %d RSS to queues - %lu", flow_i % 2, count.hits);
			total_rss += count.hits;
		}
	}
	DOCA_LOG_DBG("-------------------------------------------");
	DOCA_LOG_DBG("TOTAL INGRESS TRAFFIC:%lu", total_ingress);
	DOCA_LOG_DBG("TOTAL RSS TRAFFIC:%lu", total_rss);
	DOCA_LOG_DBG("TOTAL EGRESS TRAFFIC:%lu", total_egress);
	DOCA_LOG_DBG("TOTAL INGRESS NON_L4 TRAFFIC:%lu", total_ingress_non_l4);
	DOCA_LOG_DBG("TOTAL DROPPED TRAFFIC:%lu", total_dropped);
}

void
dpdk_init(struct application_dpdk_config *app_dpdk_config)
{
	int ret = 0;

	/* Check that DPDK enabled the required ports to send/receive on */
	ret = rte_eth_dev_count_avail();
	if (app_dpdk_config->port_config.nb_ports > 0 &&
		ret != app_dpdk_config->port_config.nb_ports)
		APP_EXIT("Application will only function with %u ports, num_of_ports=%d",
			app_dpdk_config->port_config.nb_ports, ret);

	/* Check for available logical cores */
	ret = rte_lcore_count();
	if (app_dpdk_config->port_config.nb_queues > 0 &&
		ret < app_dpdk_config->port_config.nb_queues)
		APP_EXIT("At least %u cores are needed for the application to run, available_cores=%d",
			app_dpdk_config->port_config.nb_queues, ret);
	else
		app_dpdk_config->port_config.nb_queues = ret;

	if (app_dpdk_config->reserve_main_thread)
		app_dpdk_config->port_config.nb_queues -= 1;

	if (app_dpdk_config->port_config.nb_ports > 0 &&
		dpdk_ports_init(&app_dpdk_config->port_config) != 0)
		APP_EXIT("Ports allocation failed");

	/* Enable hairpin queues */
	if (app_dpdk_config->port_config.nb_hairpin_q > 0)
		enable_hairpin_queues(app_dpdk_config->port_config.nb_ports);

	if (app_dpdk_config->sft_config.enable)
		dpdk_sft_init(app_dpdk_config);
}

void
dpdk_fini(struct application_dpdk_config *app_dpdk_config)
{
	int ret = 0;
	uint16_t port_id;
	struct rte_sft_error sft_error;
	struct rte_flow_error rte_error;

	if (app_dpdk_config->sft_config.enable) {
		ret = rte_sft_fini(&sft_error);
		if (ret < 0)
			DOCA_LOG_ERR("SFT fini failed, error=%d", ret);
	}

	for (port_id = 0; port_id < app_dpdk_config->port_config.nb_ports; port_id++) {
		ret = rte_flow_flush(port_id, &rte_error);
		if (ret != 0)
			DOCA_LOG_ERR("Flushing port failed: err=%d, port=%u", ret, port_id);

		ret = unbind_hairpin_queues(port_id);
		if (ret != 0)
			DOCA_LOG_ERR("Disabling hairpin queues failed: err=%d, port=%u",
					ret, port_id);
	}
	for (port_id = 0; port_id < app_dpdk_config->port_config.nb_ports; port_id++) {
		ret = rte_eth_dev_stop(port_id);
		if (ret != 0)
			DOCA_LOG_ERR("rte_eth_dev_stop: err=%d, port=%u", ret, port_id);

		ret = rte_eth_dev_close(port_id);
		if (ret != 0)
			DOCA_LOG_ERR("rte_eth_dev_close: err=%d, port=%u", ret, port_id);
	}
	DOCA_LOG_DBG("DPDK fini is done");
}
