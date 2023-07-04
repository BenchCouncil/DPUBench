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

#ifndef DNS_FILTER_H
#define DNS_FILTER_H

/* Libraries for doca_log */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <flow_offload.h>
#include <arg_parser.h>

#ifdef __cplusplus
extern "C" {
#endif

void dns_filter_init(struct application_dpdk_config *dpdk_config);
void dns_filter_cleanup(unsigned int nb_ports);
void process_packets(unsigned int nb_queues, unsigned int nb_ports);
extern void print_l4_header_gpu_wrapper(struct rte_ipv4_hdr *gpu_ipv4_hdr, uint8_t ip_hdr_len);

#ifdef __cplusplus
}
#endif

#endif /* DNS_FILTER_H */
