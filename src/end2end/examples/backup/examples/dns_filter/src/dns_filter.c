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
#include <flow_offload.h>
#include <utils.h>
#include <arg_parser.h>
#include <sys/socket.h>

#include "dns_filter_core.h"

/*
 *  The main function, which does initialization
 *  of the rules and starts the process of filtering the DNS packets.
 */
int
main(int argc, char **argv)
{
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 1,
		.port_config.nb_hairpin_q = 4,
		.sft_config = {0},
	};

	/* init and start parsing */
	struct doca_program_general_config *doca_general_config;
	struct doca_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = false,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("dns_filter", &type_config, NULL);
	arg_parser_start(argc, argv, &doca_general_config);

	/* update queues and ports */
	dpdk_init(&dpdk_config);

	/* init dns filter */
	dns_filter_init(&dpdk_config);

	/* process packets */
	process_packets(dpdk_config.port_config.nb_queues, dpdk_config.port_config.nb_ports);

	/* closing and releasing resources */
	dns_filter_cleanup(dpdk_config.port_config.nb_ports);

	return 0;
}
