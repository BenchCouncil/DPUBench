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

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_malloc.h>
#include <rte_regexdev.h>

#include <flow_offload.h>
#include <utils.h>
#include <arg_parser.h>

DOCA_LOG_REGISTER(FILE_SCAN);

#define MAX_FILE_NAME 255

/*
 * File Scan App configuration.
 */
struct file_scan_config {
	char			rules_file_name[MAX_FILE_NAME];
	char			data_file_name[MAX_FILE_NAME];
	uint32_t		device_id;
	uint32_t		nb_jobs;		/* Total number of jobs to divide the data file into */
	uint32_t		regex_nb_queues;	/* Number of queues to use */
	uint32_t		regex_qp_id;		/*  regex qp id to use */
	char			*data_buffer;		/* Holds the Data file contents */
	char			*rules_buffer;		/* Holds the Rules file contents, may be null after starting regdev */
	long			data_buffer_len;	/* length of the data buffer in bytes */
	long			rules_buffer_len;	/* length of the rules buffer in bytes */
	struct rte_regex_ops	*qp_desc;
	struct rte_mbuf		*data_mbuf;		/* mbuf to hold the data_file data in the mempool */
	struct rte_mempool	*mbuf_pool;		/* the memory pool */
};

static void
validate_regexdev(void)
{
	int nb_regex_devs = rte_regexdev_count();

	DOCA_LOG_DBG("Found %d RegEx device(s)", nb_regex_devs);

	if (nb_regex_devs == 0)
		APP_EXIT("Regex device was not initalized successfully");
}

static int
configure_qp(uint32_t device_id, uint32_t qp_id)
{
	struct rte_regexdev_qp_conf qp_cfg = {.cb = NULL, .nb_desc = 256, .qp_conf_flags = 0x0};
	int res = rte_regexdev_queue_pair_setup(device_id, qp_id, &qp_cfg);

	DOCA_LOG_DBG("Configuring RegEx queue pair [qp_id = %d, device_id = %d]", qp_id, device_id);

	if (res < 0)
		APP_EXIT("Could not configure queue pair [qp_id=%d, device_id=%d]", qp_id,
			 device_id);
	return res;
}

static void
configure_regexdev(struct file_scan_config *app_cfg)
{
	struct rte_regexdev_config regex_cfg;
	struct rte_regexdev_info regex_info;
	int res;

	DOCA_LOG_DBG("Configuring RegEx device [id=%d]", app_cfg->device_id);

	res = rte_regexdev_info_get(app_cfg->device_id, &regex_info);
	if (res != 0)
		APP_EXIT("Could not get RegEx device information, error code %d", res);
	if (regex_info.max_payload_size < app_cfg->data_buffer_len)
		APP_EXIT("The maximum file size is %d bytes", regex_info.max_payload_size);

	regex_cfg.rule_db = app_cfg->rules_buffer;
	regex_cfg.rule_db_len = app_cfg->rules_buffer_len;
	regex_cfg.nb_max_matches = regex_info.max_matches;
	regex_cfg.nb_queue_pairs = app_cfg->regex_nb_queues;
	regex_cfg.nb_rules_per_group = regex_info.max_rules_per_group;
	regex_cfg.nb_groups = 1;
	regex_cfg.dev_cfg_flags = 0x0;

	res = rte_regexdev_configure(app_cfg->device_id, &regex_cfg);

	rte_free(app_cfg->rules_buffer); /* No need to hold the rules db anymore */
	app_cfg->rules_buffer = NULL;

	if (res < 0)
		APP_EXIT("Could not configure RegEx device [error=%d]", res);

	configure_qp(app_cfg->device_id, app_cfg->regex_qp_id);
}

static void
allocate_mbuf_pool(struct file_scan_config *app_cfg)
{
	const int MAX_MBUF_NAME = 20;
	char mbuf_name[MAX_MBUF_NAME];
	const unsigned int mbuf_pool_size = 1;
	const int max_buffer_size = RTE_PKTMBUF_HEADROOM + app_cfg->data_buffer_len;

	DOCA_LOG_DBG("Allocating mbuf pool");

	snprintf(mbuf_name, MAX_MBUF_NAME, "CORE[%d]-POOL", rte_lcore_id());

	/* In this example we will send the whole data file as 1 mbuf struct */
	app_cfg->mbuf_pool = rte_pktmbuf_pool_create(mbuf_name, mbuf_pool_size, 0, 0,
						     max_buffer_size, rte_socket_id());
	if (app_cfg->mbuf_pool == NULL)
		APP_EXIT("Could not allocate mbuf [%s]", mbuf_name);
}

static void
extbuf_free_cb(void *addr __rte_unused, void *fcb_opaque __rte_unused)
{
}

static void
allocate_file_to_mempool(struct file_scan_config *app_cfg)
{
	struct rte_mbuf_ext_shared_info shinfo = {.free_cb = extbuf_free_cb};

	DOCA_LOG_DBG("Allocating file to mempool");

	app_cfg->data_mbuf = rte_pktmbuf_alloc(app_cfg->mbuf_pool);
	if (app_cfg->data_mbuf == NULL)
		APP_EXIT("Could not allocate memory");
	rte_pktmbuf_attach_extbuf(app_cfg->data_mbuf, app_cfg->data_buffer, 0,
				  app_cfg->data_buffer_len, &shinfo);
	app_cfg->data_mbuf->data_len = app_cfg->data_buffer_len;
	app_cfg->data_mbuf->pkt_len = app_cfg->data_buffer_len;
}

static struct rte_regex_ops *
regex_enqueue_task(struct file_scan_config *app_cfg, uint32_t qp_id)
{
	static int user_id = 1;
	struct rte_regexdev_info regex_info;
	struct rte_regex_ops *qp_desc;
	uint32_t nb_enqueues = 0;

	rte_regexdev_info_get(app_cfg->device_id, &regex_info);
	qp_desc = rte_malloc(
	    NULL, sizeof(*qp_desc) + regex_info.max_matches * sizeof(struct rte_regexdev_match), 0);
	qp_desc->mbuf = app_cfg->data_mbuf;
	qp_desc->user_id = user_id++;
	qp_desc->group_id0 = 1;
	do {
		nb_enqueues += rte_regexdev_enqueue_burst(app_cfg->device_id, qp_id, &qp_desc, 1);
	} while (nb_enqueues < app_cfg->nb_jobs);

	return qp_desc;
}

static void
file_scan_destroy(struct file_scan_config *app_cfg)
{
	if (app_cfg->data_buffer)
		rte_free(app_cfg->data_buffer);
	if (app_cfg->rules_buffer)
		rte_free(app_cfg->rules_buffer);
	if (app_cfg->qp_desc)
		rte_free(app_cfg->qp_desc);
	arg_parser_destroy();
}

/*
 * Returns file size in bytes
 * The function does not take ownership on the file (it does not close it!)
 * @param fp pointer to FILE
 * @return size of the given file in bytes.
 */
static long
file_get_size_in_bytes(FILE *fp)
{
	long current_position;
	long result;

	current_position = ftell(fp);
	if (current_position < 0 || fseek(fp, 0, SEEK_END) != 0)
		return -1;

	result = ftell(fp);
	if (fseek(fp, current_position, SEEK_SET) != 0)
		DOCA_LOG_DBG("Could not return file seek pointer to original state.");
	return result;
}

static void
read_file(char *file_name, char **buffer_p, long *buffer_len)
{
	FILE *fp = fopen(file_name, "r");
	long bytes_read = 0;

	if (fp == NULL)
		APP_EXIT("Could not open file [%s]", file_name);

	*buffer_len = file_get_size_in_bytes(fp);
	*buffer_p = rte_malloc("FileAlloc", sizeof(char) * (*buffer_len + 1), 0);
	if (*buffer_p == NULL || *buffer_len < 0)
		APP_EXIT("Error reading file [%s] !", file_name);
	bytes_read = fread(*buffer_p, sizeof(char), *buffer_len, fp);
	if (bytes_read != *buffer_len) {
		APP_EXIT("Could not read the whole file! [%s] [%li bytes read]", file_name,
			 bytes_read);
	}

	fclose(fp);
}

static void
rules_callback(void *config, void *param)
{
	struct file_scan_config *app_cfg = (struct file_scan_config *) config;
	char *rules_path = (char *) param;
	int len;

	len = strnlen(rules_path, MAX_FILE_NAME - 1);
	if (len == MAX_FILE_NAME)
		APP_EXIT("Rule file name too long max %d\n", MAX_FILE_NAME - 1);
	strncpy(app_cfg->rules_file_name, rules_path, MAX_FILE_NAME - 1);
}

static void
data_callback(void *config, void *param)
{
	struct file_scan_config *app_cfg = (struct file_scan_config *) config;
	char *data_path = (char *) param;
	int len;

	len = strnlen(data_path, MAX_FILE_NAME - 1);
	if (len == MAX_FILE_NAME)
		APP_EXIT("Data file name too long max %d\n", MAX_FILE_NAME - 1);
	strncpy(app_cfg->data_file_name, data_path, MAX_FILE_NAME - 1);
}

static void
register_file_scan_params()
{
	struct arg_parser_param rules_param = {
		.short_flag = "r",
		.long_flag = "rules",
		.arguments = "<path>",
		.description = "Path to precompiled rules file (rof2.binary)",
		.callback = rules_callback,
		.arg_type = ARG_PARSER_TYPE_STRING,
		.is_mandatory = true,
		.is_cli_only = false
	};
	struct arg_parser_param data_param = {
		.short_flag = "d",
		.long_flag = "data",
		.arguments = "<path>",
		.description = "Path to data file",
		.callback = data_callback,
		.arg_type = ARG_PARSER_TYPE_STRING,
		.is_mandatory = true,
		.is_cli_only = false
	};

	arg_parser_register_param(&rules_param);
	arg_parser_register_param(&data_param);
}

/*
 * Prints file_scan_config struct
 */
static void
print_app_config(struct file_scan_config *app_cfg)
{
	DOCA_LOG_DBG("Rules file name		%s", app_cfg->rules_file_name);
	DOCA_LOG_DBG("Data file name		%s", app_cfg->data_file_name);
	DOCA_LOG_DBG("Number of jobs		%d", app_cfg->nb_jobs);
	DOCA_LOG_DBG("Number of queue pairs	%d", app_cfg->regex_nb_queues);
}

/*
 * initialize file scan app config to default values
 */
static void
file_scan_init_cfg(struct file_scan_config *app_cfg)
{
	DOCA_LOG_DBG("Initializing  file scan app config");
	/* Set default values  */
	app_cfg->nb_jobs = 1;
	app_cfg->regex_nb_queues = 1;
	app_cfg->device_id = 0;
	app_cfg->regex_qp_id = 0;

	app_cfg->data_file_name[0] = '\0';
	app_cfg->data_buffer = NULL;
	app_cfg->data_buffer_len = 0;
	app_cfg->rules_file_name[0] = '\0';
	app_cfg->rules_buffer = NULL;
	app_cfg->rules_buffer_len = 0;
}

static void
file_scan_init(struct file_scan_config *app_cfg)
{
	/* Read data file and store it */
	read_file(app_cfg->data_file_name, &(app_cfg->data_buffer), &(app_cfg->data_buffer_len));
	if (app_cfg->data_buffer_len == 0)
		APP_EXIT("Data file is empty.");

	/* Read rules file and store it */
	read_file(app_cfg->rules_file_name, &(app_cfg->rules_buffer), &(app_cfg->rules_buffer_len));

	print_app_config(app_cfg);
}

static int
get_line_number(char *data, uint32_t offset, int *last_newline_idx)
{
	int res = 1, idx;

	*last_newline_idx = 0;
	for (idx = 0; idx < offset; idx++) {
		if (data[idx] == '\n') {
			*last_newline_idx = idx;
			res++;
		}
	}
	return res;
}

static void
report_results(struct file_scan_config *app_cfg)
{
	int regex_match_i, regex_match_line_nb, last_newline_idx;
	struct rte_regexdev_match match;

	/* If the max prefixes reached then the results are not correct */
	if (app_cfg->qp_desc->rsp_flags & RTE_REGEX_OPS_RSP_MAX_PREFIX_F) {
		DOCA_LOG_INFO("Error: Maximum number of prefixes reached.");
		return;
	}

	DOCA_LOG_INFO("Found %d match(es)\n", app_cfg->qp_desc->nb_matches);

	for (regex_match_i = 0; regex_match_i < app_cfg->qp_desc->nb_matches; regex_match_i++) {
		match = app_cfg->qp_desc->matches[regex_match_i];
		regex_match_line_nb = get_line_number(app_cfg->data_buffer, match.start_offset,
										&last_newline_idx);

		DOCA_LOG_INFO("Match %d:", regex_match_i);
		DOCA_LOG_INFO("\t\tLine Number:		%d", regex_match_line_nb);
		DOCA_LOG_INFO("\t\tMatch Index:		%d", match.start_offset - last_newline_idx);
		DOCA_LOG_INFO("\t\tMatch Length:		%d", match.len);
		DOCA_LOG_INFO("\t\tRule Id:		%d\n", match.rule_id);
	}
}

int
main(int argc, char **argv)
{
	struct file_scan_config app_cfg;
	uint32_t qp_desc_len;
	int nb_dequeues;

	/* init and start parsing */
	struct doca_program_general_config *doca_general_config;
	struct doca_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = false,
	};

	/* init file scan config struct */
	file_scan_init_cfg(&app_cfg);

	/* Parse cmdline/json arguments */
	arg_parser_init("file_scan", &type_config, &app_cfg);
	register_file_scan_params();
	arg_parser_start(argc, argv, &doca_general_config);

	/* Read data and rules files and store them */
	file_scan_init(&app_cfg);

	/* Check RegEx device */
	validate_regexdev();

	/* Configure RegEx device */
	configure_regexdev(&app_cfg);

	/* Allocate mbuf pool on this core */
	allocate_mbuf_pool(&app_cfg);

	/* Allocate mbuf containing data file data */
	allocate_file_to_mempool(&app_cfg);

	/* Send RegEx job */
	app_cfg.qp_desc = regex_enqueue_task(&app_cfg, app_cfg.regex_qp_id);
	qp_desc_len = 1;
	nb_dequeues = 0;
	/* Wait for the job to finish */
	do {
		/* Dequeue RegEx job. */
		nb_dequeues +=
		    rte_regexdev_dequeue_burst(app_cfg.device_id, app_cfg.regex_qp_id,
		     &(app_cfg.qp_desc), qp_desc_len);
	} while (nb_dequeues < app_cfg.nb_jobs);
	DOCA_LOG_DBG("Number of dequeues = %d", nb_dequeues);

	/* Report results */
	report_results(&app_cfg);

	/* Free allocated memory */
	file_scan_destroy(&app_cfg);
	return 0;
}
