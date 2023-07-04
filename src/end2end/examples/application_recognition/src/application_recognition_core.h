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

#ifndef APPLICATION_RECOGNITION_CORE_H
#define APPLICATION_RECOGNITION_CORE_H

#include <doca_dpi.h>

#include <dpi_worker.h>
#include <dpdk_utils.h>
#include <utils.h>
#include <sig_db.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLIENT_ID 0x1A

#define MAX_FILE_NAME 255

extern bool force_quit;

extern struct doca_dpi_ctx *dpi_ctx;

struct ar_config {
	bool print_on_match;
	bool create_csv;
	bool interactive_mode;
	bool collect_netflow_stat;
	bool ct;
	char cdo_filename[MAX_FILE_NAME];
	char csv_filename[MAX_FILE_NAME];
};

void signal_handler(int signum);

enum dpi_worker_action set_sig_db_on_match(int queue, const struct doca_dpi_result *result,
					uint32_t fid, void *user_data);

void ar_init(const struct application_dpdk_config *dpdk_config, struct ar_config *ar_config,
	     struct dpi_worker_attr *dpi_worker);

void ar_cleanup(struct application_dpdk_config *dpdk_config, struct ar_config *ar);

int send_netflow(void);

void fill_netflow(const struct doca_netflow_default_record *record);

void register_ar_params(void);

#ifdef __cplusplus
}
#endif

#endif /* APPLICATION_RECOGNITION_CORE_H */
