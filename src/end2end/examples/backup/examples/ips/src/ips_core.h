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

#ifndef IPS_CORE_H
#define IPS_CORE_H

#include <doca_dpi.h>

#include <dpi_worker.h>
#include <dpdk_utils.h>
#include <utils.h>
#include <sig_db.h>

#include "ips_worker.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CLIENT_ID 0x1A

#define MAX_FILE_NAME 255

#define NETFLOW_QUEUE_SIZE 1024

extern bool force_quit;

extern struct doca_dpi_ctx *dpi_ctx;

extern struct rte_ring *netflow_pending_ring, *netflow_freelist_ring;

struct ips_config {
	char cdo_filename[MAX_FILE_NAME];
	char csv_filename[MAX_FILE_NAME];
	bool create_csv;
	bool print_on_match;
	bool collect_netflow_stat;
};

int send_netflow(void);

void ips_init(const struct application_dpdk_config *dpdk_config,
	struct ips_config *ips_config, struct ips_worker_attr *ips_worker);

void ips_cleanup(struct ips_config *ips);

void register_ips_params(void);

void signal_handler(int signum);

#ifdef __cplusplus
}
#endif

#endif /* IPS_CORE_H */
