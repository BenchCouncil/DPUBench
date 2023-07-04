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

#ifndef _SIMPLE_FWD_PKT_H_
#define _SIMPLE_FWD_PKT_H_

#include <stdint.h>
#include <stdbool.h>
#include <doca_flow_net.h>

#define IPV4 (4)
#define IPV6 (6)

struct simple_fwd_pkt_format {

	uint8_t *l2;
	uint8_t *l3;
	uint8_t *l4;

	uint8_t l3_type;
	uint8_t l4_type;

	/* if tunnel it is the internal, if no tunnel then outer*/
	uint8_t *l7;
};

struct simple_fwd_pkt_tun_format {
	bool l2;
	enum doca_flow_tun_type type;
	union {
		struct {
			doca_be32_t vni;
		};
		struct {
			doca_be32_t gre_key;
			doca_be16_t proto;
		};
		struct {
			uint8_t gtp_msg_type;
			uint8_t gtp_flags;
			doca_be32_t teid;
		};
	};
};

/**
 * @brief - packet parsing result.
 *  points to relevant point in packet and
 *  classify it.
 */
struct simple_fwd_pkt_info {
	void *orig_data;
	uint16_t orig_port_id;
	uint16_t pipe_queue;
	uint32_t rss_hash;

	struct simple_fwd_pkt_format outer;
	enum doca_flow_tun_type tun_type;
	struct simple_fwd_pkt_tun_format tun;
	struct simple_fwd_pkt_format inner;
	int len;
};

struct simple_fwd_ft_key {
	doca_be32_t ipv4_1;
	doca_be32_t ipv4_2;
	doca_be16_t port_1;
	doca_be16_t port_2;
	doca_be32_t vni;
	uint8_t protocol;
	uint8_t tun_type;
	uint8_t pad[6];
	uint32_t rss_hash;
};

int
simple_fwd_parse_packet(uint8_t *data, int len,
			struct simple_fwd_pkt_info *pinfo);
uint8_t*
simple_fwd_pinfo_outer_mac_dst(struct simple_fwd_pkt_info *pinfo);
uint8_t*
simple_fwd_pinfo_outer_mac_src(struct simple_fwd_pkt_info *pinfo);
doca_be32_t
simple_fwd_pinfo_outer_ipv4_dst(struct simple_fwd_pkt_info *pinfo);
doca_be32_t
simple_fwd_pinfo_outer_ipv4_src(struct simple_fwd_pkt_info *pinfo);
doca_be32_t
simple_fwd_pinfo_inner_ipv4_src(struct simple_fwd_pkt_info *pinfo);
doca_be32_t
simple_fwd_pinfo_inner_ipv4_dst(struct simple_fwd_pkt_info *pinfo);
doca_be16_t
simple_fwd_pinfo_inner_src_port(struct simple_fwd_pkt_info *pinfo);
doca_be16_t
simple_fwd_pinfo_inner_dst_port(struct simple_fwd_pkt_info *pinfo);
doca_be16_t
simple_fwd_pinfo_outer_src_port(struct simple_fwd_pkt_info *pinfo);
doca_be16_t
simple_fwd_pinfo_outer_dst_port(struct simple_fwd_pkt_info *pinfo);
void
simple_fwd_pinfo_decap(struct simple_fwd_pkt_info *pinfo);

#endif
