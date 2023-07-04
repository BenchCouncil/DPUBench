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
#include <errno.h>
#include <sys/wait.h>

#include <cmdline_socket.h>
#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline.h>
#include <rte_compat.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include <doca_dpi.h>

#include <utils.h>

#include "url_filter_core.h"

struct cmd_create_result {
	cmdline_fixed_string_t create_db;
};

static void
cmd_create_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	create_database(DEFAULT_TXT_INPUT);
}

cmdline_parse_token_string_t cmd_create_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_create_result, create_db, "create database");

cmdline_parse_inst_t cmd_create = {
	.f = cmd_create_parsed,  /* function to call */
	.data = NULL,            /* 2nd arg of func */
	.help_str = "Delete and create a new database",
	.tokens = {              /* token list, NULL terminated */
		(void *)&cmd_create_tok,
		NULL,
	},
};

struct cmd_update_result {
	cmdline_fixed_string_t commit_db;
	cmdline_fixed_string_t file_path;
};

static void
cmd_update_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_update_result *path_data = (struct cmd_update_result *)parsed_result;

	compile_and_load_signatures(path_data->file_path, DEFAULT_CDO_OUTPUT);
}

cmdline_parse_token_string_t cmd_commit_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_update_result, commit_db, "commit database");

cmdline_parse_token_string_t cmd_path_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_update_result, file_path, NULL);

cmdline_parse_inst_t cmd_update = {
	.f = cmd_update_parsed,  /* function to call */
	.data = NULL,            /* 2nd arg of func */
	.help_str = "Update the DPI database in filepath - default is /tmp/signature.txt",
	.tokens = {              /* token list, NULL terminated */
		(void *)&cmd_commit_tok,
		(void *)&cmd_path_tok,
		NULL,
	},
};

struct cmd_filter_result {
	cmdline_fixed_string_t filter;
	cmdline_fixed_string_t proto;
	cmdline_fixed_string_t msg;
	cmdline_fixed_string_t pcre;
};

static void
cmd_filter_parsed(void *parsed_result, __rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_filter_result *filter_data = (struct cmd_filter_result *)parsed_result;

	create_url_signature(DEFAULT_TXT_INPUT, filter_data->msg, filter_data->pcre);
}

cmdline_parse_token_string_t cmd_filter_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_filter_result, filter, "filter");

cmdline_parse_token_string_t cmd_http_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_filter_result, proto, "http");

cmdline_parse_token_string_t cmd_msg_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_filter_result, msg, NULL);

cmdline_parse_token_string_t cmd_pcre_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_filter_result, pcre, NULL);


cmdline_parse_inst_t cmd_filter = {
	.f = cmd_filter_parsed,  /* function to call */
	.data = NULL,            /* 2nd arg of func */
	.help_str = "Filter URL - 3rd argument stand for the printed name and 4th for PCRE",
	.tokens = {              /* token list, NULL terminated */
		(void *)&cmd_filter_tok,
		(void *)&cmd_http_tok,
		(void *)&cmd_msg_tok,
		(void *)&cmd_pcre_tok,
		NULL,
	},
};

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	cmdline_quit(cl);
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

cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_filter,
	(cmdline_parse_inst_t *)&cmd_update,
	(cmdline_parse_inst_t *)&cmd_create,
	NULL,
};

static int
initiate_cmdline(char *cl_shell_output)
{
	struct cmdline *cl;

	cl = cmdline_stdin_new(main_ctx, cl_shell_output);
	if (cl == NULL)
		return -1;
	cmdline_interact(cl);
	cmdline_stdin_exit(cl);
	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct url_config url_config = {0};
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
	arg_parser_init("url_filter", &type_config, &url_config);
	register_url_params();
	arg_parser_start(argc, argv, &doca_general_config);

	/* update queues and ports */
	dpdk_init(&dpdk_config);

	/* All needed preparations - Check for required files, init the DPI, etc. */
	url_filter_init(&dpdk_config, &url_config, &dpi_worker);

	/* Start the DPI processing */
	dpi_worker_lcores_run(dpdk_config.port_config.nb_queues, CLIENT_ID, dpi_worker);

	/* Initiate the interactive command line session */
	initiate_cmdline("URL FILTER>> ");

	/* End of application flow */
	url_filter_cleanup();

	return 0;
}
