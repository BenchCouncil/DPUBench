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

/*
 *                                                                                              ┌───┐ ┌────┐ ┌────┐
 *                                                                         MATCHED TRAFFIC      │DPI│ │    │ │    │
 *        FLOW_OFFLOAD_DIAGRAM                                             ┌────────────────────┤WORKERS   │ │    │
 *                                                                         │ SET STATE TO       │   │ │    │ │    │
 *                                                                         │ HAIRPIN/DROP       │   │ │    │ │    │
 *                                                                         │                    │   │ │    │ │    │
 *     ┌───────────────────────────────────────────────────────────────────┼────────────────────┼───┼─┼────┼─┼────┼──┐
 *     │                                                                   │                    │   │ │    │ │    │  │
 *     │                                                                   │                    │   │ │    │ │    │  │
 *     │     NIC HW STEERING                                               │                    └─▲─┘ └──▲─┘ └──▲─┘  │
 *     │                                                                   │                      │      │      │    │
 *     │                                                                   │                      │      │      │    │
 *     │                                                                   │                      │      │      │    │
 *     │                                                                   │                      │      │      │    │
 *     │                                                                   ▼            ┌─────────┴──────┤      │    │
 *     │                     RTE_FLOW                RTE_SFT            RTE_SFT         │                ├──────┘    │
 *     │                                                                                │      RSS       │           │
 *     │                 ┌──────────────┐         ┌────────────┐      ┌──────────┐      │                │           │
 *     │                 │              │         │            │      │ POST_SFT │      └────────────────┘           │
 *     │                 │  SFT ACTION  │         │ MARK STATE │      │          │              ▲                    │
 *     │                 │  JUMP TO     │         │ IN SFT     │      │ CHECK    │              │                    │
 *     │    L4 TRAFFIC   │  TABLE WITH  ├────────►│            ├─────►│ VALID FID├──────────────┘                    │
 *     │ ┌─────────────► │  PREDEFINED  │         │            │      │ &&       │                                   │
 *     │ │               │  ZONE        │         │            │      │ VALID    │                                   │
 *     │ │               │              │         │            │      │   STATE  │                                   │
 *     │ │               └──────────────┘         └────────────┘      └┬─────────┘                                   │
 *     │ │                                                             │                                             │
 *     │ │                                                             │                                             │
 *     │ │                                                             │HAIRPIN MATCHED                              │
 *┌────┼─┴┐                                                            │  TRAFFIC      ┌─────────┐                   │
 *│    │  │                                                            └───────────────►         │              ┌────┼──┐
 *│ PORT  │                         NON L4 TRAFFIC                                     │  HAIRPIN│              │    │  │
 *│ RX │  ├────────────────────────────────────────────────────────────────────────────►         │              │  PORT │
 *│    │  │                                                                            │  QUEUE  ├─────────────►│  TX│  │
 *└────┼──┘                                                                            │         │              │    │  │
 *     │                                                                               └─────────┘              └────┼──┘
 *     │_____________________________________________________________________________________________________________│
 *
 */

#ifndef FLOW_OFFLOAD_H
#define FLOW_OFFLOAD_H


#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

enum SFT_USER_STATE {
	RSS_FLOW = 0,
	HAIRPIN_MATCHED_FLOW = 1,
	HAIRPIN_SKIPPED_FLOW = 1,
	DROP_FLOW = 2,
};


struct application_port_config {
	int nb_ports; /* Set on init to 0 for don't care, required ports otherwise */
	int nb_queues; /* Set on init to 0 for don't care, required minimum cores otherwise */
	int nb_hairpin_q; /* Set on init to 0 to disable, hairpin queues otherwise */
};
struct application_sft_config {
	bool enable; /* Enable SFT */
	bool enable_ct; /* Enable connection tracking feature of SFT */
	bool enable_state_hairpin;
	bool enable_state_drop;
};
struct application_dpdk_config {
	struct application_port_config port_config;
	struct application_sft_config sft_config;
	bool reserve_main_thread;
};

void flow_offload_query_counters(void);

void dpdk_init(struct application_dpdk_config *app_dpdk_config);

void dpdk_fini(struct application_dpdk_config *app_dpdk_config);

#ifdef __cplusplus
}
#endif

#endif
