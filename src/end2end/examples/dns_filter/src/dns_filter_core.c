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

#include <signal.h>
#include <getopt.h>
#include <rte_ethdev.h>

#include <doca_flow.h>
#include <doca_log.h>

#include <dpdk_utils.h>
#include <utils.h>

#include "dns_filter_core.h"
#ifdef GPU_SUPPORT
#include "dns_filter_kernel.h"
#endif

/*
 * the number of TSC cycles to pass between
 * each two aggregatations of DNS packets
 */
#define TSC_CYCLES_LIMIT 1000000000
#define PACKET_BURST 32 /* The number of packets in the rx queue */
#define DNS_PORT 53
#define MAX_PORT_STR 128

DOCA_LOG_REGISTER(DNS_FILTER::Core);

static bool force_quit;

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static void
handle_packets_received(uint16_t packets_received, struct rte_mbuf **packets, int *dns_count)
{
	struct rte_mbuf *packet = NULL;
	uint16_t queue_id = 0;
	uint8_t ingress_port;
	uint32_t current_packet;

	for (current_packet = 0; current_packet < packets_received; current_packet++) {

		packet = packets[current_packet];

		/* Deciding the port to send the packet to */
		ingress_port = packet->port ^ 1;
#ifndef GPU_SUPPORT
		/* DPU-Only */
		print_l4_header(packet);
#else
		/* DPU + GPU */
		struct rte_ipv4_hdr *gpu_ipv4_hdr = NULL;
		struct rte_ipv4_hdr *ipv4_hdr = rte_pktmbuf_mtod_offset(packet,
		struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

		uint8_t ip_hdr_len = rte_ipv4_hdr_len(ipv4_hdr);

		gpuErrchk(cudaMalloc((void **)&gpu_ipv4_hdr,
		sizeof(struct rte_ipv4_hdr) + ip_hdr_len));

		gpuErrchk(cudaMemcpy(gpu_ipv4_hdr, ipv4_hdr,
		sizeof(struct rte_ipv4_hdr) + ip_hdr_len, cudaMemcpyHostToDevice));

		print_l4_header_gpu_wrapper(gpu_ipv4_hdr, ip_hdr_len);
#endif
	}

	/* Packet sent to port 0 or 1*/
	rte_eth_tx_burst(ingress_port, queue_id, packets, packets_received);
}

void
process_packets(unsigned int nb_queues, unsigned int nb_ports)
{
	struct rte_mbuf *packets[PACKET_BURST];
	int dns_count = 0;
	int dns_count_last = 0;
	uint64_t stc_time = rte_get_tsc_cycles();
	uint16_t nb_packets, queue;
	uint8_t ingress_port;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	while (!force_quit) {
		for (ingress_port = 0; ingress_port < nb_ports; ingress_port++) {
			for (queue = 0; queue < nb_queues; queue++) {
				/* Get number of packets received on rx queue */
				nb_packets =
				    rte_eth_rx_burst(ingress_port, queue, packets, PACKET_BURST);

				/* Check if packets received and handle them */
				if (nb_packets)
					handle_packets_received(nb_packets, packets, &dns_count);
			}

			/* Aggregate DNS packets every TSC_CYCLES_LIMIT
			 * cycles and update the counters and stc_time
			 */
			if (rte_get_tsc_cycles() - stc_time > TSC_CYCLES_LIMIT) {
				stc_time = rte_get_tsc_cycles();
				if (dns_count != dns_count_last)
					dns_count_last = dns_count;
			}
		}
	}
}

/* Builds dns flow pipe for every port */
static void
build_dns_pipe(struct doca_flow_port *port, int nb_queues,
	struct doca_flow_pipe *hairpin_pipe)
{
	struct doca_flow_match dns_match;
	struct doca_flow_fwd dns_fw;
	struct doca_flow_fwd dns_miss_fw;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_cfg dns_pipe_cfg;
	struct doca_flow_pipe *dns_pipe;
	struct doca_flow_error err = {0};
	uint16_t rss_queues[nb_queues];
	int queue_index;
	struct doca_flow_pipe_entry *entry;

	/* Allocate DNS pipe fields */
	memset(&actions, 0, sizeof(actions));
	memset(&dns_fw, 0, sizeof(dns_fw));
	memset(&dns_miss_fw, 0, sizeof(dns_miss_fw));
	memset(&dns_match, 0, sizeof(dns_match));
	memset(&dns_pipe_cfg, 0, sizeof(dns_pipe_cfg));

	dns_pipe_cfg.name = "DNS_PIPE";
	dns_pipe_cfg.match = &dns_match;
	dns_pipe_cfg.port = port;
	dns_pipe_cfg.actions = &actions;
	dns_pipe_cfg.is_root = true;

	dns_match.out_dst_ip.type = DOCA_FLOW_IP4_ADDR;
	dns_match.out_l4_type = IPPROTO_UDP;
	dns_match.out_dst_port = rte_cpu_to_be_16(DNS_PORT);

	/* Configure queues for rss fw */
	for (queue_index = 0; queue_index < nb_queues; queue_index++)
		rss_queues[queue_index] = queue_index;

	dns_fw.type = DOCA_FLOW_FWD_RSS;
	dns_fw.rss_queues = rss_queues;
	dns_fw.rss_flags = DOCA_FLOW_RSS_UDP;
	dns_fw.num_of_queues = nb_queues;

	/* Configure miss fwd for non DNS packets */
	dns_miss_fw.type = DOCA_FLOW_FWD_PIPE;
	dns_miss_fw.next_pipe = hairpin_pipe;

	dns_pipe = doca_flow_create_pipe(&dns_pipe_cfg, &dns_fw, &dns_miss_fw, &err);
	if (dns_pipe == NULL)
		APP_EXIT("DNS pipe creation FAILED: %s", err.message);

	/* Add HW offload dns rule */
	entry =
	    doca_flow_pipe_add_entry(0, dns_pipe, &dns_match, &actions, NULL, NULL, &err);
	if (entry == NULL)
		APP_EXIT("entry creation FAILED: %s", err.message);
}

static struct doca_flow_pipe *
hairpin_non_dns_packets(struct doca_flow_port *port, uint16_t port_id)
{
	struct doca_flow_match non_dns_match;
	struct doca_flow_fwd non_dns_fw;
	struct doca_flow_actions actions;
	struct doca_flow_pipe_cfg non_dns_pipe_cfg;
	struct doca_flow_pipe *non_dns_pipe;
	struct doca_flow_error err = {0};

	/* Zeroed fields are ignored , no changeable fields */
	memset(&non_dns_match, 0, sizeof(non_dns_match));
	memset(&actions, 0, sizeof(actions));
	memset(&non_dns_fw, 0, sizeof(non_dns_fw));
	memset(&non_dns_pipe_cfg, 0, sizeof(non_dns_pipe_cfg));

	non_dns_pipe_cfg.name = "HAIRPIN_NON_DNS_PIPE";
	non_dns_pipe_cfg.match = &non_dns_match;
	/* Configure the port id "owner" of pipe */
	non_dns_pipe_cfg.port = port;
	non_dns_pipe_cfg.actions = &actions;

	non_dns_fw.type = DOCA_FLOW_FWD_PORT;
	non_dns_fw.port_id = port_id ^ 1;

	non_dns_pipe = doca_flow_create_pipe(&non_dns_pipe_cfg, &non_dns_fw, NULL, &err);
	if (non_dns_pipe == NULL)
		APP_EXIT("failed to create non-DNS pipe: %s", err.message);

	doca_flow_pipe_add_entry(0, non_dns_pipe, &non_dns_match, &actions, NULL,
					 NULL, &err);
	return non_dns_pipe;
}

/* Initialize doca flow ports */
struct doca_flow_port *
dns_filter_port_init(struct doca_flow_port_cfg *port_cfg, uint8_t portid)
{
	char port_id_str[MAX_PORT_STR];
	struct doca_flow_error err = {0};
	struct doca_flow_port *port;

	memset(port_cfg, 0, sizeof(*port_cfg));
	port_cfg->port_id = portid;
	port_cfg->type = DOCA_FLOW_PORT_DPDK_BY_ID;
	snprintf(port_id_str, MAX_PORT_STR, "%d", port_cfg->port_id);
	port_cfg->devargs = port_id_str;
	port = doca_flow_port_start(port_cfg, &err);

	if (port == NULL)
		APP_EXIT("failed to initialize doca flow port: %s", err.message);
	return port;
}

void
dns_filter_close_port(uint16_t port_id)
{
	struct rte_flow_error error = {0};
	int ret;

	ret = rte_flow_flush(port_id, &error);
	if (ret < 0)
		APP_EXIT("Failed to close and release resources: %s", error.message);

	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
}

void
dns_filter_init(struct application_dpdk_config *dpdk_config)
{
	struct doca_flow_error err = {0};
	struct doca_flow_cfg dns_flow_cfg;
	struct doca_flow_port *ports[dpdk_config->port_config.nb_ports];
	struct doca_flow_port_cfg port_cfg;
	struct doca_flow_pipe *hairpin_pipe;
	uint16_t portid;

	/* Initialize doca framework */
	dns_flow_cfg.total_sessions = dpdk_config->port_config.nb_ports;
	dns_flow_cfg.queues = dpdk_config->port_config.nb_queues;
	dns_flow_cfg.is_hairpin = true;

	if (doca_flow_init(&dns_flow_cfg, &err) < 0)
		APP_EXIT("failed to init doca: %s", err.message);

	for (portid = 0; portid < dpdk_config->port_config.nb_ports; portid++) {
		/* Initialize doca flow port */
		ports[portid] = dns_filter_port_init(&port_cfg, portid);

		/* Hairpin pipes for non-dns packets */
		hairpin_pipe = hairpin_non_dns_packets(ports[portid], portid);
		if (hairpin_pipe == NULL)
			APP_EXIT("Hairpin UDP flow creation failed: %s", err.message);

		/* Dns flow pipe */
		build_dns_pipe(ports[portid], dpdk_config->port_config.nb_queues, hairpin_pipe);
	}
}

void
dns_filter_cleanup(unsigned int nb_ports)
{
	uint16_t portid;

	for (portid = 0; portid < nb_ports; portid++)
		dns_filter_close_port(portid);

	doca_flow_destroy();
	arg_parser_destroy();
}
