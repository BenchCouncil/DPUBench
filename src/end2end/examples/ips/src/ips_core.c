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

#include "ips_core.h"

DOCA_LOG_REGISTER(IPS::Core);

bool force_quit;

struct doca_dpi_ctx *dpi_ctx;
struct rte_ring *netflow_pending_ring, *netflow_freelist_ring;

static void
fill_netflow(const struct doca_netflow_default_record *record)
{
	struct doca_netflow_default_record *tmp_record;
	/* To avoid memory corruption when flows are destroyed, we copy the pointers to a
	 *	preallocated pointer inside freelist ring and enqueue it so the main thread
	 *	can send them.
	 */
	if (rte_ring_mc_dequeue(netflow_freelist_ring, (void **)&tmp_record) != 0) {
		DOCA_LOG_DBG("Placeholder queue is empty");
		return;
	}
	*tmp_record = *record;
	if (rte_ring_mp_enqueue(netflow_pending_ring, tmp_record) != 0) {
		DOCA_LOG_DBG("Netflow queue is full");
		return;
	}
}


static enum ips_worker_action
ips_worker_on_match(int queue, const struct doca_dpi_result *result, uint32_t fid, void *user_data)
{
	uint32_t sig_id = result->info.sig_id;
	struct ips_config *ips = (struct ips_config *) user_data;
	struct doca_dpi_sig_data sig_data;
	bool blocked = false;
	int ret;

	ret = doca_dpi_signature_get(dpi_ctx, result->info.sig_id, &sig_data);
	if (ret != 0)
		APP_EXIT("Failed to get signatures, error=%d", ret);

	if (sig_db_sig_info_get(sig_id) == NULL)
		sig_db_sig_info_create(sig_id, sig_data.name);
	else
		sig_db_sig_info_set(sig_id, sig_data.name);
	sig_db_sig_info_fids_inc(sig_id);

	blocked = result->info.action == DOCA_DPI_SIG_ACTION_DROP;
	if (ips->print_on_match)
		printf_signature(dpi_ctx, sig_id, fid, blocked);

	if (blocked)
		return IPS_WORKER_DROP;
	return IPS_WORKER_RSS_FLOW;
}



static void
cdo_file_callback(void *config, void *param)
{
	struct ips_config *ips = (struct ips_config *) config;
	char *cdo_file_path = (char *) param;
	uint32_t len = strnlen(cdo_file_path, MAX_FILE_NAME - 1);

	if (len == MAX_FILE_NAME)
		APP_EXIT("CDO file name is too long - MAX=%d", MAX_FILE_NAME - 1);
	if (access(cdo_file_path, F_OK) == -1)
		APP_EXIT("CDO file not found %s", cdo_file_path);
	strncpy(ips->cdo_filename, cdo_file_path, MAX_FILE_NAME - 1);
}

static void
csv_file_callback(void *config, void *param)
{
	struct ips_config *ips = (struct ips_config *) config;
	char *value = (char *) param;
	uint32_t len = strnlen(value, MAX_FILE_NAME - 1);

	if (len == 0)
		return;
	if (len >= MAX_FILE_NAME)
		APP_EXIT("CSV file name is too long - MAX=%d", MAX_FILE_NAME - 1);
	strncpy(ips->csv_filename, value, MAX_FILE_NAME - 1);
	ips->create_csv = true;
	DOCA_LOG_DBG("Enabling CSV report [%s]", ips->csv_filename);
}

static void
netflow_stat_callback(void *config, void *param)
{
	struct ips_config *ips = (struct ips_config *) config;

	DOCA_LOG_DBG("Enabling Netflow stats");
	ips->collect_netflow_stat = true;
}

static void
print_match_callback(void *config, void *param)
{
	struct ips_config *ips = (struct ips_config *) config;

	DOCA_LOG_DBG("Enabling print on match");
	ips->print_on_match = *(bool *) param;
}

int
send_netflow()
{
	int ret, err;
	int records_to_send = 0;
	int records_sent = 0;
	int ring_count = rte_ring_count(netflow_pending_ring);
	const struct doca_netflow_template *netflow_template;
	static struct doca_netflow_default_record *records[NETFLOW_QUEUE_SIZE];
	/* Get default template */
	netflow_template = doca_netflow_template_default_get();
	if (netflow_template == NULL)
		return -1;

	/*
	 * Sending the record array
	 * The while loop ensure that all records have been sent, in case just some sent
	 * This section should happan periodically with updated flows
	 */
	if (ring_count == 0)
		return 0;
	/* We need to dequeue only the records that were enqueued with the allocated memory. */
	records_to_send = rte_ring_dequeue_bulk(netflow_pending_ring,
			(void **)records, ring_count, NULL);
	while (records_sent < records_to_send) {
		ret =
		    doca_netflow_exporter_send(netflow_template,
						(const void **)(records + records_sent),
						records_to_send - records_sent, &err);
		if (ret == -1) {
			DOCA_LOG_ERR("Failed to send Netflow, error=%d", err);
			return ret;
		}
		records_sent += ret;
	}

	DOCA_LOG_DBG("Successfully sent %d netflow records with default template.", records_sent);
	if ((int)rte_ring_enqueue_bulk(netflow_freelist_ring,
		(void **)records, records_sent, NULL) != records_sent) {
		DOCA_LOG_ERR("Placetholder queue mismatch");
		return -1;

	}
	return 0;
}

void
ips_init(const struct application_dpdk_config *dpdk_config,
	struct ips_config *ips_config, struct ips_worker_attr *ips_worker)
{
	int ret, i, err;
	static struct doca_netflow_default_record data_to_send[NETFLOW_QUEUE_SIZE];
	static struct doca_netflow_default_record *data_to_send_ptr[NETFLOW_QUEUE_SIZE];
	struct doca_dpi_config_t doca_dpi_config = {
		/* Total number of DPI queues - set according to the number of cores */
		.nb_queues = 0,
		/* Maximum job size in bytes for regex scan match */
		.max_sig_match_len = 5000,
		/* Max amount of FIDS per DPI queue */
		.max_packets_per_queue = 100000,
	};

	sig_db_init();

	/* Init Netflow plugin */
	if (ips_config->collect_netflow_stat) {
		DOCA_LOG_DBG("Enabling netflow");
		/* NULL -> Default location for the configuration file /etc/doca_netflow.conf */
		ret = doca_netflow_exporter_init(NULL);
		if (ret < 0) {
			APP_EXIT("Netflow init failed, check configuration file");
		} else {
			netflow_pending_ring = rte_ring_create("netflow_queue",
						NETFLOW_QUEUE_SIZE, SOCKET_ID_ANY, RING_F_SC_DEQ);
			netflow_freelist_ring =
				rte_ring_create("placeholder_netflow_queue", NETFLOW_QUEUE_SIZE,
								SOCKET_ID_ANY, RING_F_SP_ENQ);
			if (netflow_pending_ring == NULL || netflow_freelist_ring == NULL)
				APP_EXIT("Ring init failed");
			for (i = 0; i < NETFLOW_QUEUE_SIZE; i++)
				data_to_send_ptr[i] = &data_to_send[i];
			if (rte_ring_enqueue_bulk(netflow_freelist_ring,
				(void **)data_to_send_ptr,
				NETFLOW_QUEUE_SIZE - 1, NULL) != NETFLOW_QUEUE_SIZE - 1)
				APP_EXIT("Filling place holder failed");
		}
	}

	/* Configure regex device and queues */
	doca_dpi_config.nb_queues =  dpdk_config->port_config.nb_queues;
	dpi_ctx = doca_dpi_init(&doca_dpi_config, &err);
	if (dpi_ctx == NULL)
		APP_EXIT("DPI init failed");
	if (doca_dpi_load_signatures(dpi_ctx, ips_config->cdo_filename) != 0)
		APP_EXIT("Loading DPI signature failed");

	if (ips_config->collect_netflow_stat)
		ips_worker->send_netflow_record = fill_netflow;
	ips_worker->dpi_on_match = ips_worker_on_match;
	ips_worker->user_data = (void *)ips_config;
	ips_worker->dpi_ctx = dpi_ctx;
}

void
ips_cleanup(struct ips_config *ips)
{
	struct rte_sft_error error;
	int ret;

	ips_worker_lcores_stop(dpi_ctx);

	sig_db_destroy();

	if (ips->collect_netflow_stat) {
		doca_netflow_exporter_destroy();
		rte_ring_free(netflow_pending_ring);
		rte_ring_free(netflow_freelist_ring);
	}

	doca_dpi_destroy(dpi_ctx);
	ret = rte_sft_fini(&error);
	if (ret < 0)
		APP_EXIT("SFT fini failed, error=%d", ret);
}

void
register_ips_params()
{
	struct arg_parser_param cdo_param = {
		.short_flag = "c",
		.long_flag = "cdo",
		.arguments = NULL,
		.description = "Path to CDO file that was compiled from a valid PDD",
		.callback = cdo_file_callback,
		.arg_type = ARG_PARSER_TYPE_STRING,
		.is_mandatory = true,
		.is_cli_only = false
	};
	struct arg_parser_param csv_param = {
		.short_flag = "o",
		.long_flag = "output-csv",
		.arguments = NULL,
		.description = "Path to the output of the CSV file",
		.callback = csv_file_callback,
		.arg_type = ARG_PARSER_TYPE_STRING,
		.is_mandatory = false,
		.is_cli_only = false
	};
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
	struct arg_parser_param netflow_param = {
		.short_flag = "n",
		.long_flag = "netflow",
		.arguments = NULL,
		.description = "Collect Netflow statistics and send according to conf file",
		.callback = netflow_stat_callback,
		.arg_type = ARG_PARSER_TYPE_BOOLEAN,
		.is_mandatory = false,
		.is_cli_only = false
	};
	arg_parser_register_param(&cdo_param);
	arg_parser_register_param(&csv_param);
	arg_parser_register_param(&netflow_param);
	arg_parser_register_param(&print_on_match_param);
}

void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}
