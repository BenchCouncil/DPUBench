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

#ifndef URL_FILTER_CORE_H
#define URL_FILTER_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include <arg_parser.h>
#include <flow_offload.h>
#include <dpi_worker.h>

#define CLIENT_ID 0x1A

#define DEFAULT_TXT_INPUT "/tmp/signature.txt"
#define DEFAULT_CDO_OUTPUT "/tmp/signature.cdo"

typedef void (*print_callback)(uint32_t, const char *, uint32_t);

struct url_config {
	bool print_on_match;
	bool ct;
};

void create_database(const char *signature_filename);

void compile_and_load_signatures(const char *signature_filename,
		const char *cdo_filename);

void create_url_signature(const char *signature_filename, const char *msg,
		const char *pcre);

void url_filter_init(const struct application_dpdk_config *dpdk_config,
		const struct url_config *url_config, struct dpi_worker_attr *dpi_worker);

void url_filter_cleanup(void);

void register_url_params(void);

void print_match_callback(void *config, void *param);

void connection_tracking_callback(void *config, void *param);

#ifdef __cplusplus
}
#endif

#endif /* URL_FILTER_CORE_H */
