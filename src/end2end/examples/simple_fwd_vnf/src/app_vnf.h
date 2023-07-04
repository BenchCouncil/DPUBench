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
#ifndef _APP_VNF_H_
#define _APP_VNF_H_

#include <stdint.h>

struct simple_fwd_pkt_info;

struct app_vnf {
	int (*vnf_init)(void *p);
	int (*vnf_process_pkt)(struct simple_fwd_pkt_info *pinfo);
	void (*vnf_flow_age)(uint16_t queue);
	int (*vnf_destroy)(void);
};

#endif
