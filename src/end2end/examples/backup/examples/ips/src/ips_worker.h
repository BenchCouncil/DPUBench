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

#ifndef IPS_WORKER_H
#define IPS_WORKER_H

#include <doca_dpi.h>

#include "flow_offload.h"
#include "doca_netflow.h"

#ifdef __cplusplus
extern "C" {
#endif

enum ips_worker_action {
	IPS_WORKER_DROP,
	IPS_WORKER_RSS_FLOW
};

struct ips_worker_attr {
	/* Will be called on (first) match */
	enum ips_worker_action (*dpi_on_match)(int queue, const struct doca_dpi_result *result,
					       uint32_t fid, void *user_data);
	void (*send_netflow_record)(const struct doca_netflow_default_record *record);

	void *user_data;
	struct doca_dpi_ctx *dpi_ctx;
};

void ips_worker_lcores_run(int available_cores, int client_id, struct ips_worker_attr attr);

void ips_worker_lcores_stop(struct doca_dpi_ctx *dpi_ctx);

void printf_signature(struct doca_dpi_ctx *dpi_ctx, uint32_t sig_id, uint32_t fid, bool blocked);

#ifdef __cplusplus
}
#endif

#endif
