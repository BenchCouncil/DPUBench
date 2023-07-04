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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include <rte_sft.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <cmdline_socket.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline.h>

#include <doca_dpi.h>
#include <doca_log.h>

#include <utils.h>
#include <arg_parser.h>
#include <sig_db.h>

#include "application_recognition_core.h"

DOCA_LOG_REGISTER(AR);

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	cmdline_quit(cl);
	force_quit = true;
}

cmdline_parse_token_string_t cmd_quit_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,  /* function to call */
	.data = NULL,          /* 2nd arg of func */
	.help_str = "Exit application",
	.tokens = {            /* token list, NULL terminated */
		(void *)&cmd_quit_tok,
		NULL,
	},
};

struct cmd_block_result {
	cmdline_fixed_string_t block;
	uint32_t sig_id;
};

static void
cmd_block_parsed(void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_block_result *block_data = (struct cmd_block_result *)parsed_result;

	cmdline_printf(cl, "Blocking sig_id=%d!\n", block_data->sig_id);
	sig_db_sig_info_set_block_status(block_data->sig_id, true);
}

cmdline_parse_token_string_t cmd_block_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_block_result, block, "block");

cmdline_parse_token_num_t cmd_fid_tok =
	TOKEN_NUM_INITIALIZER(struct cmd_block_result, sig_id, RTE_UINT32);

cmdline_parse_inst_t cmd_block = {
	.f = cmd_block_parsed,  /* function to call */
	.data = NULL,           /* 2nd arg of func */
	.help_str = "Block signature ID",
	.tokens = {             /* token list, NULL terminated */
		(void *)&cmd_block_tok,
		(void *)&cmd_fid_tok,
		NULL,
	},
};

static void
cmd_unblock_parsed(void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_block_result *block_data = (struct cmd_block_result *)parsed_result;

	cmdline_printf(cl, "Unblocking sig_id=%d!\n", block_data->sig_id);
	sig_db_sig_info_set_block_status(block_data->sig_id, false);
}

cmdline_parse_token_string_t cmd_unblock_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_block_result, block, "unblock");

cmdline_parse_inst_t cmd_unblock = {
	.f = cmd_unblock_parsed,  /* function to call */
	.data = NULL,		  /* 2nd arg of func */
	.help_str = "Unblock signature ID",
	.tokens = {		  /* token list, NULL terminated */
		(void *)&cmd_unblock_tok,
		(void *)&cmd_fid_tok,
		NULL,
	},
};

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_block,
	(cmdline_parse_inst_t *)&cmd_unblock,
	NULL,
};

static int
initiate_cmdline(char *cl_shell_prompt)
{
	struct cmdline *cl;

	cl = cmdline_stdin_new(main_ctx, cl_shell_prompt);
	if (cl == NULL)
		return -1;
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);
	return 0;
}

int
main(int argc, char *argv[])
{
	int ret;
	pthread_t cmdline_thread;
	struct ar_config ar_config = {0};
	struct dpi_worker_attr dpi_worker = {0};
	struct application_dpdk_config dpdk_config = {
		.port_config.nb_ports = 2,
		.port_config.nb_queues = 2,
		.port_config.nb_hairpin_q = 4,
		.sft_config = {1, 1, 1, 1},
		.reserve_main_thread = true,
	};

	/* init and start parsing */
	struct doca_program_general_config *doca_general_config;
	struct doca_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = false,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("application_recognition", &type_config, &ar_config);
	register_ar_params();
	arg_parser_start(argc, argv, &doca_general_config);

	/* update queues and ports */
	dpdk_init(&dpdk_config);

	/* AR application init */
	ar_init(&dpdk_config, &ar_config, &dpi_worker);

	/* Start the DPI processing */
	dpi_worker_lcores_run(dpdk_config.port_config.nb_queues, CLIENT_ID, dpi_worker);

	if (ar_config.interactive_mode) {
		ret = rte_ctrl_thread_create(&cmdline_thread, "cmdline_thread", NULL,
			(void *)initiate_cmdline, "APPLICATION RECOGNITION>> ");
		if (ret != 0)
			APP_EXIT("Thread creation failed");
	} else {
		DOCA_LOG_INFO("Non-interactive mode - Ctrl+C to quit.");
		force_quit = false;
		signal(SIGINT, signal_handler);
		signal(SIGTERM, signal_handler);
	}
	/* The main thread loop to collect statistics */
	while (!force_quit) {
		if (ar_config.create_csv) {
			sleep(1);
			if (sig_database_write_to_csv(ar_config.csv_filename) != 0)
				APP_EXIT("CSV file access failed");
		}
		if (ar_config.collect_netflow_stat && send_netflow() != 0)
			APP_EXIT("Unexpected Netflow failure");
	}

	/* Clearing threads */
	if (ar_config.interactive_mode)
		pthread_kill(cmdline_thread, 0);

	/* AR application cleanup */
	ar_cleanup(&dpdk_config, &ar_config);

	return 0;
}
