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
#include <rte_malloc.h>

#include "dpi_worker.h"
#include "dpdk_utils.h"
#include "utils.h"
#include "simple_fwd_port.h"

DOCA_LOG_REGISTER(DWRKR);

#define SFT_ZONE 0xcafe
#define BURST_SIZE 1024
#define MAX_DPI_DEPTH (1 << 30)
#define IPV6_HDR_LEN_NO_EXT 40
#define NETFLOW_UPDATE_RATE 1000
#define NUM_APP 3
#define HW 0

#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))

#define G(x) (x^2 + x | 12318934 + x ^ 14123)
#define F(x, y) (x + G(y) * x / 1024)
#define H(x) F(x, x + G(x))

#define MAGIC 0x3124fabcd
#define HUFFMAN_ON2(x) (x ^ 15 * 2 + MAGIC)
#define SNAPPY_ONP(x) (HUFFMAN_ON2(x) + HUFFMAN_ON2(x) * 2)
#define COMPRESS_IDKITSNM(x, y) (HUFFMAN_ON2(HUFFMAN_ON2(x) + SNAPPY_ONP(HUFFMAN_ON2(x))) * HUFFMAN_ON2(y + SNAPPY_ONP(x ^ 2 + 1123)))

enum flow_status {
	NEW_FLOW,
	EXISTING_FLOW,
	DROPPED_FLOW,
	CLOSED_FLOW,
	OOO_FLOW,
	INVALID_FLOW,
};

bool force_quit;

struct flow_info {
	uint32_t sig_id;
	uint64_t byte_count[2];
	uint8_t state;
	struct doca_dpi_flow_ctx *dpi_flow_ctx;
	struct doca_netflow_default_record record[2];
};

struct worker_ctx {
	uint8_t queue_id;
	uint8_t client_id;
	uint16_t ingress_port;
	uint32_t packets_to_dequeue;
	struct dpi_worker_attr attr;
};

struct sft_status_wrapper {
	struct rte_sft_flow_status sft_status;
	uint32_t data[1];
};

static void
set_netflow_record(struct flow_info *flow, const struct worker_ctx *ctx, bool initiator)
{
	struct doca_netflow_default_record *record_to_send;

	if (ctx->attr.send_netflow_record == NULL)
		return;
	record_to_send = &flow->record[initiator];

	record_to_send->last = time(0);
	ctx->attr.send_netflow_record(record_to_send);
	/* Only the difference is relevant between Netflow interations */
	record_to_send->d_pkts = 0;
	record_to_send->d_octets = 0;
}

/*
 * The reverse_stpl takes a 7 tuple as an input and reverses it.
 * 5-tuple reversal is ordinary while the zone stays the same for both
 * directions. The last piece of the 7-tuple is the port which is also reversed.
 */

static void
reverse_stpl(struct rte_sft_7tuple *rstpl, const struct rte_sft_7tuple *stpl)
{
	memset(rstpl, 0, sizeof(*rstpl));
	rstpl->flow_5tuple.is_ipv6 = stpl->flow_5tuple.is_ipv6;
	rstpl->flow_5tuple.proto = stpl->flow_5tuple.proto;
	if (rstpl->flow_5tuple.is_ipv6) {
		memcpy(&rstpl->flow_5tuple.ipv6.src_addr[0], &stpl->flow_5tuple.ipv6.dst_addr[0],
			16);
		memcpy(&rstpl->flow_5tuple.ipv6.dst_addr[0], &stpl->flow_5tuple.ipv6.src_addr[0],
			16);
	} else {
		rstpl->flow_5tuple.ipv4.src_addr = stpl->flow_5tuple.ipv4.dst_addr;
		rstpl->flow_5tuple.ipv4.dst_addr = stpl->flow_5tuple.ipv4.src_addr;
	}
	rstpl->flow_5tuple.src_port = stpl->flow_5tuple.dst_port;
	rstpl->flow_5tuple.dst_port = stpl->flow_5tuple.src_port;
	rstpl->zone = stpl->zone;
	rstpl->port_id = stpl->port_id ^ 1;
}

static int
set_l4_parsing_info(struct doca_dpi_parsing_info *parsing_info, uint32_t *payload_offset,
		    const struct rte_sft_mbuf_info *mbuf_info)
{
	*payload_offset += ((mbuf_info->l4_hdr - (void *)mbuf_info->eth_hdr));
	parsing_info->ethertype = rte_cpu_to_be_16(mbuf_info->eth_type);
	parsing_info->l4_protocol = mbuf_info->l4_protocol;

	if (!mbuf_info->is_ipv6)
		parsing_info->dst_ip.ipv4.s_addr = mbuf_info->ip4->dst_addr;
	else
		memcpy(&parsing_info->dst_ip.ipv6,  &mbuf_info->ip6->dst_addr[0], 16);
	switch (parsing_info->l4_protocol) {
	case IPPROTO_UDP:
		*payload_offset += 8;
		parsing_info->l4_sport = mbuf_info->udp->src_port;
		parsing_info->l4_dport = mbuf_info->udp->dst_port;
		break;
	case IPPROTO_TCP:
		*payload_offset += ((struct rte_tcp_hdr *)mbuf_info->l4_hdr)->data_off/4;
		parsing_info->l4_sport = mbuf_info->tcp->src_port;
		parsing_info->l4_dport = mbuf_info->tcp->dst_port;
		break;
	default:
		DOCA_LOG_DBG("Unsupported L4 protocol!");
		return -1;
	}
	return 0;
}

static void
client_obj_flow_info_create(uint32_t key, const struct worker_ctx *ctx,
				const struct rte_sft_5tuple *five_tuple)
{
	struct flow_info *flow = (struct flow_info *)rte_zmalloc(NULL, sizeof(struct flow_info), 0);
	struct rte_sft_error error;

	if (flow == NULL)
		APP_EXIT("RTE Malloc failed");

	strcpy(flow->record[1].application_name, "NO_MATCH");
	flow->record[1].flow_id = key;
	if (!five_tuple->is_ipv6) {
		flow->record[1].src_addr_v4 = five_tuple->ipv4.src_addr;
		flow->record[1].dst_addr_v4 = five_tuple->ipv4.dst_addr;
	} else {
		memcpy(&flow->record[1].src_addr_v6, five_tuple->ipv6.src_addr, 16);
		memcpy(&flow->record[1].dst_addr_v6, five_tuple->ipv6.dst_addr, 16);
	}
	flow->record[1].src_port = five_tuple->src_port;
	flow->record[1].dst_port = five_tuple->dst_port;
	flow->record[1].protocol = five_tuple->proto;
	flow->record[1].input = ctx->ingress_port;
	flow->record[1].output =  ctx->ingress_port ^ 1;
	flow->record[1].first = time(0);
	flow->record[1].last = time(0);

	strcpy(flow->record[0].application_name, "NO_MATCH");
	flow->record[0].flow_id = key;
	if (!five_tuple->is_ipv6) {
		flow->record[0].src_addr_v4 = five_tuple->ipv4.dst_addr;
		flow->record[0].dst_addr_v4 = five_tuple->ipv4.src_addr;
	} else {
		memcpy(&flow->record[0].src_addr_v6, five_tuple->ipv6.dst_addr, 16);
		memcpy(&flow->record[0].dst_addr_v6, five_tuple->ipv6.src_addr, 16);
	}
	flow->record[0].src_port = five_tuple->dst_port;
	flow->record[0].dst_port = five_tuple->src_port;
	flow->record[0].protocol = five_tuple->proto;
	flow->record[0].input =  ctx->ingress_port ^ 1;
	flow->record[0].output =  ctx->ingress_port;
	flow->record[0].first = time(0);
	flow->record[0].last = time(0);

	if (rte_sft_flow_set_client_obj(ctx->queue_id, key, ctx->client_id, flow, &error) != 0)
		APP_EXIT("Failed adding key to SFT, error=%s", error.message);
}

static void
client_obj_flow_info_set(const char *app_name, uint32_t sig_id, struct flow_info *data)
{
	assert(data != NULL);
	data->sig_id = sig_id;
	memcpy(data->record[0].application_name, app_name, 64);
	memcpy(data->record[1].application_name, app_name, 64);
}

static void
debug_dpi_dequeue_status(int dpi_result, int status_flags, int fid)
{
	if (status_flags & DOCA_DPI_STATUS_LAST_PACKET)
		DOCA_LOG_DBG("Indicates this is the last packet in DPI queue");
	if (status_flags & DOCA_DPI_STATUS_NEW_MATCH)
		DOCA_LOG_DBG("Indicates flow was matched");
}

static int
skip_dpi_and_update_byte_count(struct flow_info *flow, const struct rte_sft_flow_status *status,
	 const struct rte_mbuf *packet, uint32_t payload_offset)
{
	if (flow->state == HAIRPIN_MATCHED_FLOW) {
		DOCA_LOG_DBG("FID %d already matched, skipping...", status->fid);
		return HAIRPIN_MATCHED_FLOW;
	} else if (flow->state == HAIRPIN_SKIPPED_FLOW) {
		DOCA_LOG_DBG("FID %d depth exceeded, skipping...", status->fid);
		return HAIRPIN_SKIPPED_FLOW;
	} else if (flow->byte_count[status->initiator] > MAX_DPI_DEPTH) {
		DOCA_LOG_DBG("FID %d exceeded %d bytes, skipping...", status->fid, MAX_DPI_DEPTH);
		// flow->state = HAIRPIN_SKIPPED_FLOW;
		return HAIRPIN_SKIPPED_FLOW;
	}
	/* Add packet's payload length to avoid inspecting if MAX_DPI_DEPTH is reached */
	flow->byte_count[status->initiator] += rte_pktmbuf_pkt_len(packet) - payload_offset;
	return RSS_FLOW;
}

static bool
drop_flow(const struct worker_ctx *ctx, const struct doca_dpi_result *result, uint32_t fid)
{
	if (ctx->attr.dpi_on_match && ctx->attr.dpi_on_match(ctx->queue_id, result, fid,
		ctx->attr.user_data) == DPI_WORKER_DROP)
		return true;
	return false;
}

void
update_record_counters(struct worker_ctx *ctx, struct flow_info **flow,
		       const struct rte_mbuf *packet, const bool initiator)
{
	(*flow)->record[initiator].d_pkts++;
	(*flow)->record[initiator].d_octets += rte_pktmbuf_pkt_len(packet);

	/* Every predefined number of packets, we send a Netflow record */
	if ((*flow)->record[initiator].d_pkts % NETFLOW_UPDATE_RATE == 0)
		set_netflow_record((*flow), ctx, initiator);
}

static int
process_mbuf_to_fid(struct rte_mbuf *packet, struct rte_mbuf **mbuf_out,
	struct worker_ctx *ctx, struct rte_sft_flow_status *sft_status, struct flow_info **flow,
	struct rte_sft_mbuf_info *mbuf_info)
{
	int ret = 0;
	int sft_state = 0;
	uint32_t data = 1;
	struct rte_sft_7tuple stpl, rstpl;
	struct rte_sft_actions_specs sft_action = {RTE_SFT_ACTION_AGE | RTE_SFT_ACTION_COUNT,
							NULL, NULL, 0 /* Use default aging */};
	struct rte_sft_error error;
	bool new_flow = false;

	ret = rte_sft_parse_mbuf(packet, mbuf_info, NULL, &error);
	if (ret != 0) {
		DOCA_LOG_DBG("SFT parse MBUF failed, error=%s", error.message);
		return INVALID_FLOW;
	}
	DOCA_LOG_DBG("Processing SFT mbuf");
	if (rte_sft_process_mbuf(ctx->queue_id, packet, mbuf_out, sft_status, &error) != 0)
		APP_EXIT("SFT failed, error=%s", error.message);
	if (!sft_status->activated) {
		if (!sft_status->zone_valid) {
			*mbuf_out = NULL;
			DOCA_LOG_DBG("Processing SFT zone");
			ret = rte_sft_process_mbuf_with_zone(ctx->queue_id, packet,
				SFT_ZONE, mbuf_out, sft_status, &error);
			if (ret != 0)
				APP_EXIT("SFT zone failed, error=%s", error.message);
		}

		if (!sft_status->activated) {
			rte_sft_mbuf_stpl(packet, mbuf_info, sft_status->zone, &stpl, &error);
			reverse_stpl(&rstpl, &stpl);
			DOCA_LOG_DBG("Activating SFT flow");
			ret = rte_sft_flow_activate(ctx->queue_id, SFT_ZONE /*Fixed zone*/, packet,
				&rstpl, sft_state, &data, 1 /*proto_enable*/,
				&sft_action, 0 /*dev_id*/, ctx->ingress_port,
				mbuf_out, sft_status, &error);
			if (ret != 0)
				APP_EXIT("SFT activate failed, error=%s", error.message);
			else if (sft_status->proto_state == SFT_CT_STATE_ERROR) {
				DOCA_LOG_DBG("SFT_CT_STATE_ERROR, packet is freed");
				rte_pktmbuf_free(packet);
			}
			/* Uses set_client_obj- see function */
			client_obj_flow_info_create(sft_status->fid, ctx, &stpl.flow_5tuple);
			new_flow = true;
		}
	}
	if (*mbuf_out == NULL)
		return OOO_FLOW;
	*flow = (struct flow_info *)rte_sft_flow_get_client_obj(ctx->queue_id, sft_status->fid,
		ctx->client_id, &error);
	if (*flow == NULL)
		APP_EXIT("Client object get failed, error=%s", error.message);
	/* Netflow statistics */
	update_record_counters(ctx, flow, *mbuf_out, sft_status->initiator);
	if (new_flow) {
		return NEW_FLOW;
	} else if (sft_status->proto_state == SFT_CT_STATE_CLOSED) {
		if (rte_sft_flow_destroy(ctx->queue_id, sft_status->fid, &error) != 0)
			DOCA_LOG_ERR("SFT flow destroy failed, error=%s", error.message);
		return CLOSED_FLOW;
	} else if ((*flow)->state == DROP_FLOW) {
		rte_pktmbuf_free(*mbuf_out);
		*mbuf_out = NULL;
		return DROPPED_FLOW;
	}
	return EXISTING_FLOW;
}

static void
debug_dpi_enqueue_status(int ret, bool initiator, uint32_t payload_offset)
{
	switch (ret) {
	case DOCA_DPI_ENQ_PROCESSING:
		DOCA_LOG_DBG("Packet was enqueued to DPI with payload offset of %u bytes, initiator=%u",
				payload_offset, initiator);
		// printf("Packet was enqueued to DPI with payload offset of %u bytes, initiator=%u\n",
		//		payload_offset, initiator);

		break;
	case DOCA_DPI_ENQ_PACKET_EMPTY:
		DOCA_LOG_DBG("Packet has no payload to inspect");
                // printf("Packet has no payload to inspect\n");
		break;
	case DOCA_DPI_ENQ_BUSY:
		DOCA_LOG_DBG("DPI queue is full, enqueueing was not possible");
                // printf("DPI queue is full, enqueueing was not possible\n");
		break;
	case DOCA_DPI_ENQ_INVALID_DB:
		DOCA_LOG_DBG("Invalid/Missing database, enqueueing was not possible");
		// printf("Invalid/Missing database, enqueueing was not possible\n");
		break;
	default:
		APP_EXIT("Packet enqueue failed, error=%d", ret);
		break;
	}
}

static void
resolve_dpi_match(struct flow_info *flow, const struct doca_dpi_result *result,
		  struct doca_dpi_sig_data *sig_data, const struct worker_ctx *ctx)
{
	uint32_t fid = flow->record[ctx->ingress_port].flow_id;
	struct rte_sft_error error;

	DOCA_LOG_DBG("FID %u matches sig_id %d", fid, result->info.sig_id);
    	
	if (drop_flow(ctx, result, fid))
		flow->state = DROP_FLOW;
	else
		flow->state = HAIRPIN_MATCHED_FLOW;

	if (rte_sft_flow_set_state(ctx->queue_id, fid, flow->state, &error) != 0)
		APP_EXIT("Setting flow state failed");

	doca_dpi_signature_get(ctx->attr.dpi_ctx, result->info.sig_id, sig_data);
	client_obj_flow_info_set(sig_data->name, result->info.sig_id, flow);
	/* Update match for both Netflow directions */
	set_netflow_record(flow, ctx, true);
	set_netflow_record(flow, ctx, false);
}

static void
resolve_dpi_destroy(struct flow_info *flow, const struct worker_ctx *ctx)
{
	uint32_t fid = flow->record[ctx->ingress_port].flow_id;

	set_netflow_record(flow, ctx, true);
	set_netflow_record(flow, ctx, false);
	/* In some scenarios it is possible to have a SFT flow without DPI flow */
	if (flow->dpi_flow_ctx == NULL)
		return;
	doca_dpi_flow_destroy(flow->dpi_flow_ctx);
	DOCA_LOG_DBG("DPI FID %d was destroyed", fid);
	flow->dpi_flow_ctx = NULL;
	rte_free(flow);
	flow = NULL;
}

static void
dequeue_packets(struct worker_ctx *ctx)
{
	int dpi_result = 0;
	uint32_t fid;
	struct flow_info *flow = NULL;
	struct doca_dpi_result result = {0};
	struct doca_dpi_sig_data sig_data = {0};

	DOCA_LOG_DBG("------------ DPI DEQUEUE ----------");
	while (ctx->packets_to_dequeue) {
		dpi_result = doca_dpi_dequeue(ctx->attr.dpi_ctx, ctx->queue_id, &result);
		if (dpi_result == DOCA_DPI_DEQ_NA) {
			DOCA_LOG_DBG("Indicates dequeue not possible as device is NA");
			return;
		}
		if (result.status_flags & DOCA_DPI_STATUS_DESTROYED) {
			DOCA_LOG_DBG("Indicates flow was destroyed while enqueued");
			ctx->packets_to_dequeue--;
			continue;
		}
		/* User data must be extracted, because "flow" might not be valid anymore
		 * if destroyed
		 */
		flow = (struct flow_info *)result.user_data;
		assert(flow != NULL);
		fid = flow->record[ctx->ingress_port].flow_id;
		debug_dpi_dequeue_status(dpi_result, result.status_flags, fid);

		if (result.matched && (result.status_flags & DOCA_DPI_STATUS_NEW_MATCH))
			resolve_dpi_match(flow, &result, &sig_data, ctx);
		else if (result.matched)
			DOCA_LOG_DBG("FID %u was already matched", fid);
		else
			DOCA_LOG_DBG("FID %u was not matched", fid);
		ctx->packets_to_dequeue--;
	}
	DOCA_LOG_DBG("------------ END OF DPI DEQUEUE ----------");
}

static void
resolve_dpi_enqueue(struct flow_info *flow, const struct rte_sft_flow_status *sft_status,
		    struct rte_mbuf *packet, uint32_t payload_offset, struct worker_ctx *ctx)
{
	int ret;
	int state;
	uint32_t fid = flow->record[ctx->ingress_port].flow_id;
	struct rte_sft_error error;

	state = skip_dpi_and_update_byte_count(flow, sft_status, packet, payload_offset);
	if (state != RSS_FLOW) {
		if (rte_sft_flow_set_state(ctx->queue_id, fid, state, &error) != 0)
			APP_EXIT("Setting flow state failed");
		return;
	}
	for (;;) {
		ret = doca_dpi_enqueue(flow->dpi_flow_ctx, packet,
			sft_status->initiator, payload_offset, flow);
		// printf("%d\n", ret);
		debug_dpi_enqueue_status(ret, sft_status->initiator, payload_offset);
		if (ret == DOCA_DPI_ENQ_INVALID_DB)
			return;
		if (ret !=  DOCA_DPI_ENQ_BUSY)
			break;
		dequeue_packets(ctx);
	}
	if (ret == DOCA_DPI_ENQ_PROCESSING)
		ctx->packets_to_dequeue += 1;
}

static char* get_mbuf_data(struct rte_mbuf* mbuf) {
	static char buffer[1024];

	for (int i = 0; i < mbuf->pkt_len / 24; i++) buffer[i] = H(i);

	return buffer;
}

static void match_pkt(char* data, int len) {
    for (int i = 0; i < len / 24; i++) {
		int x = F(i, i);
	}
}

static int do_dpi_cpu(int len, struct rte_mbuf* mbuf) {
    int sig_id = 0;

    for (int i = 0; i < len / 24 ; i++) {
		char* data = get_mbuf_data(mbuf);
		match_pkt(data, len);
		sig_id = rand() % 3;
	}

    return sig_id;
}

static void
resolve_dpi_enqueue_cpu(struct flow_info *flow, const struct rte_sft_flow_status *sft_status,
		    struct rte_mbuf *packet, uint32_t payload_offset, struct worker_ctx *ctx)
{
	int ret;
	int state;
	uint32_t fid = flow->record[ctx->ingress_port].flow_id;
	struct rte_sft_error error;

	state = skip_dpi_and_update_byte_count(flow, sft_status, packet, payload_offset);
	if (state != RSS_FLOW) {
		if (rte_sft_flow_set_state(ctx->queue_id, fid, state, &error) != 0)
			APP_EXIT("Setting flow state failed");
		return;
	}
	for (;;) {
		ret = doca_dpi_enqueue(flow->dpi_flow_ctx, packet,
			sft_status->initiator, payload_offset, flow);
		int len = packet->pkt_len;
		do_dpi_cpu(len, packet);
		// printf("%d\n", ret);
		debug_dpi_enqueue_status(ret, sft_status->initiator, payload_offset);
		if (ret == DOCA_DPI_ENQ_INVALID_DB)
			return;
		if (ret !=  DOCA_DPI_ENQ_BUSY)
			break;
		dequeue_packets(ctx);
	}
	if (ret == DOCA_DPI_ENQ_PROCESSING)
		ctx->packets_to_dequeue += 1;
}

static void
forward_packets(struct rte_mbuf **packets, uint16_t burst_size, const struct worker_ctx *ctx)
{
	uint16_t nb_tx;
	uint16_t remaining_packets = burst_size;

	do {
		/* Send burst of TX packets to the egress port */
		nb_tx = rte_eth_tx_burst(ctx->ingress_port ^ 1,
			ctx->queue_id, packets, remaining_packets);
		/* Port 0 - 1 vice versa. 0 is the P0 and 1 is PF0HPF */
		DOCA_LOG_DBG("Forwarded %d packets to port=0x%x", nb_tx, ctx->ingress_port^1);
		packets += nb_tx;
		remaining_packets -= nb_tx;
	} while (remaining_packets > 0);
}

static void
handle_and_forward_ooo(struct rte_sft_flow_status *sft_status, struct worker_ctx *ctx)
{
	int ret;
	int drained_packets = 0;
	int packets_to_drain = sft_status->nb_in_order_mbufs;
	uint16_t packet_index;
	uint32_t payload_offset = 0;
	struct rte_sft_error error;
	struct rte_mbuf *packet = NULL;
	struct rte_mbuf *drain_buff[BURST_SIZE];
	struct rte_sft_mbuf_info mbuf_info = {0};
	struct doca_dpi_parsing_info parsing_info = {0};
	struct flow_info *flow = (struct flow_info *)rte_sft_flow_get_client_obj(ctx->queue_id,
		sft_status->fid, ctx->client_id, &error);

	do {
		DOCA_LOG_DBG("Draining %d packets", packets_to_drain);
		drained_packets = rte_sft_drain_mbuf(ctx->queue_id, sft_status->fid, drain_buff,
			BURST_SIZE, sft_status->initiator, sft_status, &error);
		DOCA_LOG_DBG("Drained %d packets", drained_packets);
		packets_to_drain -= drained_packets;
		if (drained_packets < 0)
			APP_EXIT("SFT MBUF drain failed, error=%s", error.message);
		for (packet_index = 0; packet_index < drained_packets; packet_index++) {
			packet = drain_buff[packet_index];
			ret = rte_sft_parse_mbuf(packet, &mbuf_info, NULL, &error);
			if (ret != 0)
				APP_EXIT("Parse MBUF failed, error=%s", error.message);
			if (set_l4_parsing_info(&parsing_info, &payload_offset, &mbuf_info) != 0)
				continue;
			resolve_dpi_enqueue(flow, sft_status, packet, payload_offset, ctx);
			payload_offset = 0;
		}
		forward_packets(drain_buff, packet_index, ctx);
	} while (packets_to_drain > 0);
}

static void
debug_flow_status(uint32_t fid, int flow_status, int queue_id)
{
	switch (flow_status) {
	case NEW_FLOW:
		DOCA_LOG_DBG("FID %u is new, creating new DPI flow, queue_id %d", fid, queue_id);
		// printf("FID %u is new, creating new DPI flow, queue_id %d\n", fid, queue_id);
		break;
	case EXISTING_FLOW:
		DOCA_LOG_DBG("FID %u exists, enqueueing packet to DPI", fid);
		// printf("FID %u exists, enqueueing packet to DPI\n", fid);
		break;
	case DROPPED_FLOW:
		DOCA_LOG_DBG("FID %u is blocked, skipping DPI", fid);
		// printf("FID %u is blocked, skipping DPI\n", fid);
		break;
	case CLOSED_FLOW:
		DOCA_LOG_DBG("FID %u was closed, destroying DPI flow", fid);
		// printf("FID %u was closed, destroying DPI flow\n", fid);
		break;
	case OOO_FLOW:
		DOCA_LOG_DBG("FID %u is out of order, packet needs to be drained", fid);
		// printf("FID %u is out of order, packet needs to be drained\n", fid);
		break;
	case INVALID_FLOW:
		DOCA_LOG_DBG("FID %u is invalid, protocol unsupported", fid);
		// printf("FID %u is invalid, protocol unsupported\n", fid);
		break;
	}
}

static void
enqueue_packet(struct rte_mbuf *buf_in, struct rte_mbuf **mbuf_out, struct worker_ctx *ctx,
	       struct rte_sft_flow_status *sft_status)
{
	int flow_status, error;
	uint32_t payload_offset = 0;
	struct rte_sft_mbuf_info mbuf_info = {0};
	struct doca_dpi_parsing_info parsing_info = {0};
	struct doca_dpi_sig_data sig_data = {0};
	struct doca_dpi_result result = {0};
	struct flow_info *flow = NULL;
	struct rte_mbuf *packet;

	DOCA_LOG_DBG("------------ DPI ENQUEUE ----------");
	flow_status = process_mbuf_to_fid(buf_in, mbuf_out, ctx, sft_status, &flow, &mbuf_info);
	debug_flow_status(sft_status->fid, flow_status, ctx->queue_id);
	if (flow_status == INVALID_FLOW ||
	    set_l4_parsing_info(&parsing_info, &payload_offset, &mbuf_info) != 0) {
		*mbuf_out = buf_in;
		return;
	} else if (*mbuf_out == NULL)
		return;
	packet = *mbuf_out;
	print_header_info(packet, true, true, true);

	switch (flow_status) {
	case NEW_FLOW:
		// printf("new flow created\n");
		flow->dpi_flow_ctx = doca_dpi_flow_create(ctx->attr.dpi_ctx, ctx->queue_id,
							  &parsing_info, &error, &result);
		set_netflow_record(flow, ctx, sft_status->initiator);
		if (error < 0)
			APP_EXIT("DPI flow creation failed, error=%d", error);
		/* Flow matched based on parsing info */
		else if (result.matched) {
			resolve_dpi_match(flow, &result, &sig_data, ctx);
			return;
		}
		/* FALLTHROUGH */
	case EXISTING_FLOW:
		// printf("flow already exist\n");
		resolve_dpi_enqueue(flow, sft_status, packet, payload_offset, ctx);
		break;

	case CLOSED_FLOW:
                // printf("flow closed\n");
		assert(flow != NULL);
		resolve_dpi_destroy(flow, ctx);
		break;
	}
	DOCA_LOG_DBG("------------ DPI ENQUEUE END----------");
}

static void
enqueue_packet_cpu(struct rte_mbuf *buf_in, struct rte_mbuf **mbuf_out, struct worker_ctx *ctx,
	       struct rte_sft_flow_status *sft_status)
{
	int flow_status, error;
	uint32_t payload_offset = 0;
	struct rte_sft_mbuf_info mbuf_info = {0};
	struct doca_dpi_parsing_info parsing_info = {0};
	struct doca_dpi_sig_data sig_data = {0};
	struct doca_dpi_result result = {0};
	struct flow_info *flow = NULL;
	struct rte_mbuf *packet;

	DOCA_LOG_DBG("------------ DPI ENQUEUE ----------");
	flow_status = process_mbuf_to_fid(buf_in, mbuf_out, ctx, sft_status, &flow, &mbuf_info);
	debug_flow_status(sft_status->fid, flow_status, ctx->queue_id);
	if (flow_status == INVALID_FLOW ||
	    set_l4_parsing_info(&parsing_info, &payload_offset, &mbuf_info) != 0) {
		*mbuf_out = buf_in;
		return;
	} else if (*mbuf_out == NULL)
		return;
	packet = *mbuf_out;
	print_header_info(packet, true, true, true);

	switch (flow_status) {
	case NEW_FLOW:
		// printf("new flow created\n");
		flow->dpi_flow_ctx = doca_dpi_flow_create(ctx->attr.dpi_ctx, ctx->queue_id,
							  &parsing_info, &error, &result);
		set_netflow_record(flow, ctx, sft_status->initiator);
		if (error < 0)
			APP_EXIT("DPI flow creation failed, error=%d", error);
		/* Flow matched based on parsing info */
		else if (result.matched) {
			resolve_dpi_match(flow, &result, &sig_data, ctx);
			return;
		}
		/* FALLTHROUGH */
	case EXISTING_FLOW:
		// printf("flow already exist\n");
		resolve_dpi_enqueue_cpu(flow, sft_status, packet, payload_offset, ctx);
		break;

	case CLOSED_FLOW:
                // printf("flow closed\n");
		assert(flow != NULL);
		resolve_dpi_destroy(flow, ctx);
		break;
	}
	DOCA_LOG_DBG("------------ DPI ENQUEUE END----------");
}

static void
clear_aged_flows(const struct worker_ctx *ctx)
{
	int aged_flows, fid_index;
	uint32_t fid;
	uint32_t *fid_list = NULL;
	struct flow_info *flow = NULL;
	struct rte_sft_error error;
	/* if nb_fids is 0, return the number of all aged out SFT flows. */
	aged_flows = rte_sft_flow_get_aged_flows(ctx->queue_id, fid_list, /* nb_fids */ 0, &error);
	if (aged_flows <= 0)
		return;
	fid_list = (uint32_t *)rte_zmalloc(NULL, sizeof(uint32_t) * aged_flows, 0);
	if (fid_list == NULL)
		APP_EXIT("RTE malloc failed");
	/* if nb_fids is not 0 , return the number of aged out flows - IT HAS TO BE EQUAL */
	if (rte_sft_flow_get_aged_flows(ctx->queue_id, fid_list, aged_flows, &error) < 0)
		APP_EXIT("SFT get aged flows has failed, error=%s", error.message);
	for (fid_index = 0; fid_index < aged_flows; fid_index++) {
		fid = fid_list[fid_index];
		DOCA_LOG_DBG("FID %u will be removed due to aging", fid);
		flow = (struct flow_info *)rte_sft_flow_get_client_obj(ctx->queue_id, fid,
			ctx->client_id, &error);
		assert(flow != NULL);
		resolve_dpi_destroy(flow, ctx);
		if (rte_sft_flow_destroy(ctx->queue_id, fid, &error) != 0)
			DOCA_LOG_ERR("FID %u destroy failed", fid);
	}
	rte_free(fid_list);
}

static int get_choice(int cnt) {
    return rand() % cnt;
}

static void
do_hash(int length) {
    long l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
    H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
    long K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    l = length + ((length % 64 > 56) ? (128 - length % 64) : (64 - length % 64));
	char rainbow[7] = "asdasd";
    for (i = 0; i < length; rainbow[rand() % 5] = rand() % 255, i++);
    for (rainbow[(rand() % 5 + 123) % 5], i++; i < l; rainbow[(rand() % 5 + 123) % 5] = 0, i++);
    for (int h = 0; h < l; h += 64) {
        for (i = 0; i < 16; W[i] = rand() % 89, i++);
        for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 64; i++) {
            T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
            T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
            H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
    }
  
}

static void
do_compress(int length) {
    int cnt[26];
    for (int i = 0; i < 26; i++) cnt[i] = 0;
    for (int i = 0; i < length; i++) {
	int c = rand() % 26;
	cnt[c]++;
    }

    for (int i = 0; i < length; i++) {
	int man = cnt[i] % 789123;

	int stg1 = COMPRESS_IDKITSNM(i, man);
	int stg2 = SNAPPY_ONP(stg1);
	int stg3 = HUFFMAN_ON2(stg1);

	int res = COMPRESS_IDKITSNM(SNAPPY_ONP(HUFFMAN_ON2(stg1)), HUFFMAN_ON2(stg1 + stg2));
    }
}

static void
do_nonsense() {
    char reply[30];
    
    int rnd = rand() % 3;

    if (rnd == 0)
	reply[0] = 'o', reply[1] = 'k';

	if (rnd == 1) {
	    reply[0] = 'h';
	    reply[1] = 'e';
	    reply[2] = 'l';
	    reply[3] = 'l';
	    reply[4] = 'o';
	}

	if (rnd == 2) {
	    reply[0] = 'G';
	    reply[2] = 'o';
	    reply[3] = 'o';
	    reply[4] = 'd';
	    reply[5] = '!';
	}
}

static void
do_some_work_cpu(struct rte_mbuf* mbuf) {
	int len = mbuf->pkt_len;

	int choice = get_choice(NUM_APP);

	switch (choice)
	{
	case 0:
	    do_hash(len);
		break;
	case 1:
	    do_compress(len);
		break;
	default:
	    do_nonsense();
		break;
	} 
}

static void
process_packet(struct worker_ctx *ctx)
{
	int packet_number = 0;
	uint16_t non_filtered_packets = 0;
	struct sft_status_wrapper sft_status_wrapper = { {0} };
	struct rte_sft_flow_status *sft_status = &(sft_status_wrapper.sft_status);
	/* Get burst of RX packets from ingress port */
	struct rte_mbuf *buf_in[BURST_SIZE], *buf_out[BURST_SIZE];
	const uint16_t nb_rx =
		rte_eth_rx_burst(ctx->ingress_port, ctx->queue_id, buf_in, BURST_SIZE);
	if (nb_rx != 0) {
	        // printf("%d\n", nb_rx);
		DOCA_LOG_DBG("Received %d packets from port 0x%x using core %u",
			nb_rx, ctx->ingress_port, rte_lcore_id());
		/* Inspect each packet in the buffer */
		for (packet_number = 0; packet_number < nb_rx; packet_number++) {
			memset(sft_status, 0, sizeof(struct rte_sft_flow_status));
			if (HW) {
			    enqueue_packet(buf_in[packet_number],
				    &buf_out[non_filtered_packets], ctx, sft_status);
			}
			else {
			    enqueue_packet_cpu(buf_in[packet_number],
			        &buf_out[non_filtered_packets], ctx, sft_status);
			    do_some_work_cpu(buf_in[packet_number]);
			}

			/* If mbuf is NULL, either an error happened or packet is OOO/fragmeneted */
			if (buf_out[non_filtered_packets] == NULL) {
				printf("some pkts nonfiltered\n");
				/* Forward all the valid packets in mbuf_out up until now  */
				if (non_filtered_packets) {
					forward_packets(buf_out, non_filtered_packets, ctx);
					non_filtered_packets = 0;
				}
			} else
				non_filtered_packets++;
			if (sft_status->nb_in_order_mbufs) {
				printf("in_order_mbuf is : %d\n", sft_status->nb_in_order_mbufs);
				/* If nb_in_order_mbuds > 0, an inorder packet has arrived, first we
				 * have to send it and then handle OOO packets.
				 */
				if (non_filtered_packets) {
					forward_packets(buf_out, non_filtered_packets, ctx);
					non_filtered_packets = 0;
				}
				handle_and_forward_ooo(sft_status, ctx);
			}
		}
		if (non_filtered_packets)
			forward_packets(buf_out, non_filtered_packets, ctx);
	}
	if (ctx->packets_to_dequeue) {
		// printf("dequeue packets : %d\n", ctx->packets_to_dequeue);
		dequeue_packets(ctx);
	}

	clear_aged_flows(ctx);
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

static void
dpi_worker(void *worker)
{
	uint8_t nb_ports = rte_eth_dev_count_avail();
	uint8_t port;
	struct worker_ctx *ctx = (struct worker_ctx *)worker;
	uint32_t core_id = rte_lcore_id();

	DOCA_LOG_DBG("Core %u is forwarding packets.", rte_lcore_id());
	/* Run until the application is quit or killed */
	uint64_t last_tsc = rte_rdtsc();
	while (!force_quit) {
		if (core_id == 1) {
		    uint64_t cur_tsc = rte_rdtsc();
		    if (cur_tsc > last_tsc + 2 * rte_get_timer_hz()) {
                        simple_fwd_dump_port_stats(0);
			last_tsc = cur_tsc;
		    }
		}
		for (port = 0; port < nb_ports; port++) {
			ctx->ingress_port = port;
			process_packet(ctx);
		}
	}
	rte_free(ctx);
}

void
dpi_worker_lcores_stop(struct doca_dpi_ctx *dpi_ctx)
{
	struct doca_dpi_stat_info doca_stat = {0};

	force_quit = true;
	rte_eal_mp_wait_lcore();
	/* Print DPI statistics */
	doca_dpi_stat_get(dpi_ctx, true, &doca_stat);
	DOCA_LOG_DBG("------------- DPI STATISTICS --------------");
	DOCA_LOG_DBG("Packets scanned:%d", doca_stat.nb_scanned_pkts);
	DOCA_LOG_DBG("Matched signatures:%d", doca_stat.nb_matches);
	DOCA_LOG_DBG("TCP matches:%d", doca_stat.nb_tcp_based);
	DOCA_LOG_DBG("UDP matches:%d", doca_stat.nb_udp_based);
	DOCA_LOG_DBG("HTTP matches:%d", doca_stat.nb_http_parser_based);
	DOCA_LOG_DBG("SSL matches:%d", doca_stat.nb_ssl_parser_based);
	DOCA_LOG_DBG("Miscellaneous L4:%d, L7:%d", doca_stat.nb_other_l4, doca_stat.nb_other_l7);
}

void
printf_signature(struct doca_dpi_ctx *dpi_ctx, uint32_t sig_id, uint32_t fid, bool blocked)
{
	int ret;
	struct doca_dpi_sig_data sig_data;

	ret = doca_dpi_signature_get(dpi_ctx, sig_id, &sig_data);
	if (ret != 0)
		APP_EXIT("Failed to get signatures, error=%d", ret);
	DOCA_LOG_INFO("SIG ID: %u, APP Name: %s, SFT_FID: %u, Blocked: %u", sig_id, sig_data.name,
		fid, blocked);
}

/* This is the main worker calling function, each queue represents a core */
void
dpi_worker_lcores_run(int nb_queues, int app_client_id, struct dpi_worker_attr attr)
{
	int current_lcore = 0;
	uint16_t lcore_index = 0;
	struct worker_ctx *ctx = NULL;

	DOCA_LOG_INFO("%d cores are used as DPI workers", nb_queues);
	while ((current_lcore != RTE_MAX_LCORE) && (lcore_index < nb_queues)) {
		current_lcore = rte_get_next_lcore(current_lcore, true, false);
		ctx = (struct worker_ctx *)rte_zmalloc(NULL, sizeof(struct worker_ctx), 0);
		if (ctx == NULL)
			APP_EXIT("RTE malloc failed");
		ctx->client_id = app_client_id;
		ctx->queue_id = lcore_index;
		ctx->attr = attr;
		if (rte_eal_remote_launch((void *)dpi_worker, (void *)ctx, current_lcore) != 0)
			APP_EXIT("Remote launch failed");
		ctx++;
		lcore_index++;
	}
}
