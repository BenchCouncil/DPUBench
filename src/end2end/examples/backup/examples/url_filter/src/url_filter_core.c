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

#include <rte_compat.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_sft.h>

#include <doca_dpi.h>
#include <doca_log.h>

#include <utils.h>

#include "url_filter_core.h"

#define COMPILER_PATH "/usr/bin/doca_dpi_compiler"
#define MAX_COMMAND_LENGTH 255

DOCA_LOG_REGISTER(UFLTR::Core);

static uint32_t global_sig_id;
static struct doca_dpi_ctx *dpi_ctx;

void
create_database(const char *signature_filename)
{
	FILE *url_signature_file;
	int errno_output;

	if (remove(signature_filename) != 0) {
		errno_output = errno;
		DOCA_LOG_DBG("File removal failed : error %d", errno_output);
	}
	url_signature_file = fopen(signature_filename, "w");
	if (url_signature_file == NULL) {
		DOCA_LOG_ERR("Failed to open signature file");
		return;
	}
	fclose(url_signature_file);
	global_sig_id = 1;
}

void
compile_and_load_signatures(const char *signature_filename, const char *cdo_filename)
{
	int status, errno_output;
	char command_buffer[MAX_COMMAND_LENGTH];

	if (access(signature_filename, F_OK) != 0) {
		DOCA_LOG_ERR("Signature file is missing - check PATH=%s\n or \"create database\"",
		signature_filename);
		return;
	}
	status = snprintf(command_buffer, MAX_COMMAND_LENGTH, "%s -i %s -o %s -f suricata",
		COMPILER_PATH, signature_filename, cdo_filename);
	if (status == MAX_COMMAND_LENGTH) {
		DOCA_LOG_ERR("File path too long, please shorten and try again");
		return;
	}
	status = system(command_buffer);
	if (status != 0) {
		errno_output = errno;
		APP_EXIT("Signature file compilation failed : error %d", errno_output);
	}
	if (doca_dpi_load_signatures(dpi_ctx, cdo_filename) != 0)
		APP_EXIT("Loading DPI signature failed");
}

void
create_url_signature(const char *signature_filename, const char *msg, const char *pcre)
{
	FILE *url_signature_file;
	uint32_t sig_id = global_sig_id;

	url_signature_file = fopen(signature_filename, "a");
	if (url_signature_file == NULL) {
		DOCA_LOG_ERR("Failed to open signature file");
		return;
	}

	fprintf(url_signature_file, "drop tcp any any -> any any (msg:\"%s\"; flow:to_server; ",
	msg);
	fprintf(url_signature_file, "pcre:\"/%s/I\"; sid:%d;)\n", pcre, sig_id);
	fprintf(url_signature_file, "drop tcp any any -> any any (msg:\"%s\"; flow:to_server; ",
	msg);
	fprintf(url_signature_file, "tls.sni; pcre:\"/%s/\"; sid:%d;)\n", pcre, sig_id + 1);
	fclose(url_signature_file);

	DOCA_LOG_DBG("Created sig_id %d and %d", sig_id, sig_id + 1);

	global_sig_id += 2;
}

static enum dpi_worker_action
drop_on_match(int queue, const struct doca_dpi_result *result, uint32_t fid, void *user_data)
{
	int ret;
	struct doca_dpi_sig_data sig_data;
	uint32_t sig_id = result->info.sig_id;
	bool print_on_match = ((struct url_config *)user_data)->print_on_match;

	if (print_on_match) {
		ret = doca_dpi_signature_get(dpi_ctx, sig_id, &sig_data);
		if (ret != 0)
			APP_EXIT("Failed to get signatures - error=%d", ret);
		DOCA_LOG_INFO("SIG ID: %u, URL MSG: %s, SFT_FID: %u", sig_id, sig_data.name, fid);
	}
	if (result->info.action == DOCA_DPI_SIG_ACTION_DROP)
		return DPI_WORKER_DROP;
	return DPI_WORKER_ALLOW;
}

void
url_filter_init(const struct application_dpdk_config *dpdk_config,
		const struct url_config *url_config, struct dpi_worker_attr *dpi_worker)
{
	int err;
	struct doca_dpi_config_t doca_dpi_config = {
		/* Total number of DPI queues */
		.nb_queues = 0,
		/* Maximum job size in bytes for regex scan match */
		.max_sig_match_len = 5000,
		/* Max amount of FIDS per DPI queue */
		.max_packets_per_queue = 100000,
	};

	/* Check that the compiler is present */
	if (access(COMPILER_PATH, F_OK) != 0)
		APP_EXIT("Compiler is missing - check PATH=%s", COMPILER_PATH);

	/* Configure regex device and queues */
	doca_dpi_config.nb_queues = dpdk_config->port_config.nb_queues;
	dpi_ctx = doca_dpi_init(&doca_dpi_config, &err);
	if (dpi_ctx == NULL)
		APP_EXIT("DPI init failed");

	/* Starting main process on all available cores */
	dpi_worker->dpi_on_match = drop_on_match;
	dpi_worker->user_data = (void *)url_config;
	dpi_worker->dpi_ctx = dpi_ctx;
}

void
url_filter_cleanup()
{
	int ret;
	int errno_output;
	struct rte_sft_error error;

	if (remove(DEFAULT_CDO_OUTPUT) != 0) {
		errno_output = errno;
		DOCA_LOG_DBG("File removal failed : error %d", errno_output);
	}

	dpi_worker_lcores_stop(dpi_ctx);

	flow_offload_query_counters();

	doca_dpi_destroy(dpi_ctx);
	ret = rte_sft_fini(&error);
	if (ret < 0)
		APP_EXIT("SFT fini failed, error=%d", ret);
	arg_parser_destroy();
}

void
print_match_callback(void *config, void *param)
{
	struct url_config *url = (struct url_config *) config;

	url->print_on_match = *(bool *) param;
}

/* aux function, registration URL params to parser */
void
register_url_params()
{
	struct arg_parser_param print_on_match_param = {
		.short_flag = "p",
		.long_flag = "print-match",
		.arguments = NULL,
		.description = "Prints FID when matched in DPI engine",
		.callback = print_match_callback,
		.arg_type = ARG_PARSER_TYPE_BOOLEAN,
		.is_mandatory = false,
		.is_cli_only = false
	};

	arg_parser_register_param(&print_on_match_param);
}
