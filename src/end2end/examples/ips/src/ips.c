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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include <rte_sft.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <doca_dpi.h>
#include <doca_log.h>

#include <flow_offload.h>
#include <utils.h>
#include <sig_db.h>
#include <arg_parser.h>

#include "ips_worker.h"
#include "ips_core.h"

DOCA_LOG_REGISTER(IPS);

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */

int
main(int argc, char *argv[])
{
	struct ips_config ips_config = {{0}};
	struct ips_worker_attr ips_worker_attr = {0};
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 2,
		.port_config.nb_hairpin_q = 4,
		.sft_config = {
			.enable = true,
			.enable_ct = true,
			.enable_state_hairpin = false,
			.enable_state_drop = true
		},
		.reserve_main_thread = true,
	};

	/* init and start parsing */
	struct doca_program_general_config *doca_program_general_config;
	struct doca_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = false,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("ips", &type_config, &ips_config);
	register_ips_params();
	arg_parser_start(argc, argv, &doca_program_general_config);

	/** init DPDK cores and sft */
	dpdk_init(&dpdk_config);

	/* IPS init **/
	ips_init(&dpdk_config, &ips_config, &ips_worker_attr);

	/* Start the DPI processing */
	ips_worker_lcores_run(dpdk_config.port_config.nb_queues, CLIENT_ID, ips_worker_attr);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	force_quit = false;

	/* The main thread */
	while (!force_quit) {
		sleep(1);
		if (ips_config.create_csv) {
			if (sig_database_write_to_csv(ips_config.csv_filename) != 0)
				APP_EXIT("CSV file access failed");
		}
		if (ips_config.collect_netflow_stat && send_netflow() != 0)
			APP_EXIT("Unexpected Netflow failure");
	}

	/* End of application flow */
	ips_cleanup(&ips_config);

	return 0;
}
