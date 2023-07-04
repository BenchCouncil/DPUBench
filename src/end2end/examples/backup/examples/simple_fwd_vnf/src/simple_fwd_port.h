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

#ifndef _SIMPLE_FWD_PORT_H_
#define _SIMPLE_FWD_PORT_H_

#define NUM_OF_PORTS (2)

struct simple_fwd_port_cfg {
	uint16_t port_id;
	uint16_t nb_queues;
	uint16_t is_hairpin;
	bool age_thread;
};

void
simple_fwd_close_port(uint16_t port_id);

void
simple_fwd_dump_port_stats(uint16_t port_id);

#endif
