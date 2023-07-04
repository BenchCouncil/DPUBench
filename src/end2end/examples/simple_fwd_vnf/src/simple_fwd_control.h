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

#ifndef _SIMPLE_FWD_CONTROL_H_
#define _SIMPLE_FWD_CONTROL_H_

#include <stdint.h>
#include <stdbool.h>

int
simple_fwd_build_control_pipe_entry(struct doca_flow_pipe *c_pipe);

struct doca_flow_pipe *
simple_fwd_build_control_pipe(struct doca_flow_port *port);

#endif
