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

#include <doca_log.h>

#include <arg_parser.h>

#include "telemetry_client.h"

DOCA_LOG_REGISTER(TELEMETRY);

struct telemetry_params {
	bool telemetry;
	bool netflow;
};

static struct telemetry_params telemetry_app_config;

static void
set_telemetry_params(void *config, void *param)
{
	struct telemetry_params *telemetry_app_config = (struct telemetry_params *)config;

	telemetry_app_config->telemetry = *(bool *) param;
}

static void
set_telemetry_netflow_params(void *config, void *param)
{
	struct telemetry_params *telemetry_app_config = (struct telemetry_params *)config;

	telemetry_app_config->netflow = *(bool *) param;
}

static void
register_telemetry_params()
{
	struct arg_parser_param telemetry_param = {
		.short_flag = "t",
		.long_flag = "telemetry",
		.arguments = NULL,
		.description = "Run DOCA telemetry example",
		.callback = set_telemetry_params,
		.arg_type = ARG_PARSER_TYPE_BOOLEAN,
		.is_mandatory = false,
		.is_cli_only = false
	};
	struct arg_parser_param netflow_param = {
		.short_flag = "n",
		.long_flag = "netflow",
		.arguments = NULL,
		.description = "Run DOCA telemetry netflow example",
		.callback = set_telemetry_netflow_params,
		.arg_type = ARG_PARSER_TYPE_BOOLEAN,
		.is_mandatory = false,
		.is_cli_only = false
	};

	arg_parser_register_param(&telemetry_param);
	arg_parser_register_param(&netflow_param);
}

int
main(int argc, char *argv[])
{
	int ret = 0;

	/* init and start parsing */
	struct doca_program_general_config *doca_general_config;
	struct doca_program_type_config type_config = {
		.is_dpdk = false,
		.is_grpc = false,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("telemetry_client", &type_config, &telemetry_app_config);
	register_telemetry_params();
	arg_parser_start(argc, argv, &doca_general_config);

	if (telemetry_app_config.telemetry) {
		ret = telemetry_config();
		if (ret != 0)
			DOCA_LOG_ERR("DOCA Telemetry example failed");
	}

	if (telemetry_app_config.netflow) {
		ret = ret | telemetry_netflow_config();
		if (ret != 0)
			DOCA_LOG_ERR("DOCA Telemetry Netflow example failed");
	}

	arg_parser_destroy();

	return ret;
}
