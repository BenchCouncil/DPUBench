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
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include "doca_flow.h"
#include <doca_log.h>
#include "simple_fwd.h"
#include "simple_fwd_ft.h"

DOCA_LOG_REGISTER(SIMPLE_FWD_FT);

#define FT_TIMEOUT_SEC 60

struct simple_fwd_ft_bucket {
	struct simple_fwd_ft_entry_head head;
	rte_spinlock_t lock;
};

struct simple_fwd_ft_stats {
	uint64_t add;
	uint64_t rm;

	uint64_t memuse;
};

struct simple_fwd_ft_cfg {
	uint32_t size;
	uint32_t mask;
	uint32_t user_data_size;
	uint32_t entry_size;
};

struct simple_fwd_ft {
	struct simple_fwd_ft_cfg cfg;
	struct simple_fwd_ft_stats stats;

	volatile int stop_aging_thread;
	uint32_t fid_ctr;
	void (*simple_fwd_aging_cb)(struct simple_fwd_ft_user_ctx *ctx);
	void (*simple_fwd_aging_hw_cb)(void);
	struct simple_fwd_ft_bucket buckets[0];
};

static void
simple_fwd_ft_update_expiration(struct simple_fwd_ft_entry *e)
{
	uint64_t t = rte_rdtsc();
	uint64_t sec = rte_get_timer_hz();

	e->expiration = t + sec * FT_TIMEOUT_SEC;
}

static bool
simple_fwd_ft_update_counter(struct simple_fwd_ft_entry *e)
{
	struct simple_fwd_pipe_entry *entry =
		(struct simple_fwd_pipe_entry *)&e->user_ctx.data[0];
	struct doca_flow_query query_stats = { 0 };
	bool update = 0;

	if (!doca_flow_query(entry->hw_entry, &query_stats)) {
		update = !!(query_stats.total_pkts - e->last_counter);
		e->last_counter = query_stats.total_pkts;
	}
	return update;
}

static void
_ft_destroy_entry(struct simple_fwd_ft *ft,
		  struct simple_fwd_ft_entry *ft_entry)
{
	LIST_REMOVE(ft_entry, next);
	ft->simple_fwd_aging_cb(&ft_entry->user_ctx);
	free(ft_entry);
	ft->stats.rm--;
}

void
simple_fwd_ft_destroy_entry(struct simple_fwd_ft *ft,
			    struct simple_fwd_ft_entry *ft_entry)
{
	int idx = ft_entry->buckets_index;

	rte_spinlock_lock(&ft->buckets[idx].lock);
	_ft_destroy_entry(ft, ft_entry);
	rte_spinlock_unlock(&ft->buckets[idx].lock);
}

static bool
simple_fwd_ft_aging_ft_entry(struct simple_fwd_ft *ft,
			     unsigned int i)
{
	struct simple_fwd_ft_entry_head *first;
	struct simple_fwd_ft_entry *node;
	bool still_aging = false;
	uint64_t t = rte_rdtsc();

	if (rte_spinlock_trylock(&ft->buckets[i].lock)) {
		first = &ft->buckets[i].head;
		LIST_FOREACH(node, first, next) {
			if (node->expiration < t &&
					!simple_fwd_ft_update_counter(node)) {
				DOCA_LOG_DBG("aging removing flow");
				_ft_destroy_entry(ft, node);
				still_aging = true;
				break;
			}
		}
		rte_spinlock_unlock(&ft->buckets[i].lock);
	}
	return still_aging;
}

static void*
simple_fwd_ft_aging_main(void *void_ptr)
{
	struct simple_fwd_ft *ft = (struct simple_fwd_ft *)void_ptr;
	bool next = false;
	unsigned int i;

	if (!ft) {
		DOCA_LOG_CRIT("no ft, abort aging\n");
		return NULL;
	}
	while (!ft->stop_aging_thread) {
		if ((int)(ft->stats.add - ft->stats.rm) == 0)
			continue;
		DOCA_LOG_DBG("total entries: %d",
			(int)(ft->stats.add - ft->stats.rm));
		DOCA_LOG_DBG("total adds   : %d", (int)(ft->stats.add));
		for (i = 0; i < ft->cfg.size; i++) {
			do {
				next = simple_fwd_ft_aging_ft_entry(ft, i);
			} while (next);
		}
		sleep(1);
	}
	return NULL;
}

/**
 * @brief - start per flow table aging thread
 *
 * @param ft
 */
static void
simple_fwd_ft_aging_thread_start(struct simple_fwd_ft *ft)
{
	pthread_t inc_x_thread;

	/* create a second thread which executes inc_x(&x) */
	if (pthread_create(&inc_x_thread, NULL, simple_fwd_ft_aging_main, ft))
		fprintf(stderr, "Error creating thread\n");
}

int
simple_fwd_ft_key_fill(struct simple_fwd_pkt_info *pinfo,
		       struct simple_fwd_ft_key *key)
{
	bool inner = false;

	if (pinfo->tun_type != DOCA_FLOW_TUN_NONE)
		inner = true;

	/* support ipv6 */
	if (pinfo->outer.l3_type != IPV4)
		return -1;

	key->rss_hash = pinfo->rss_hash;
	/* 5-tuple of inner if there is tunnel or outer if none */
	key->protocol = inner ? pinfo->inner.l4_type : pinfo->outer.l4_type;
	key->ipv4_1 = simple_fwd_ft_key_get_ipv4_src(inner, pinfo);
	key->ipv4_2 = simple_fwd_ft_key_get_ipv4_dst(inner, pinfo);
	key->port_1 = simple_fwd_ft_key_get_src_port(inner, pinfo);
	key->port_2 = simple_fwd_ft_key_get_dst_port(inner, pinfo);

	/* in case of tunnel , use tun type and vni */
	if (pinfo->tun_type != DOCA_FLOW_TUN_NONE) {
		key->tun_type = pinfo->tun_type;
		key->vni = pinfo->tun.vni;
	}
	return 0;
}

bool
simple_fwd_ft_key_equal(struct simple_fwd_ft_key *key1,
			struct simple_fwd_ft_key *key2)
{
	uint64_t *keyp1 = (uint64_t *)key1;
	uint64_t *keyp2 = (uint64_t *)key2;
	uint64_t res = keyp1[0] ^ keyp2[0];

	res |= keyp1[1] ^ keyp2[1];
	res |= keyp1[2] ^ keyp2[2];
	return (res == 0);
}

struct simple_fwd_ft *
simple_fwd_ft_create(int nb_flows, uint32_t user_data_size,
	       void (*simple_fwd_aging_cb)(struct simple_fwd_ft_user_ctx *ctx),
	       void (*simple_fwd_aging_hw_cb)(void), bool age_thread)
{
	struct simple_fwd_ft *ft;
	uint32_t nb_flows_aligned;
	uint32_t alloc_size;
	uint32_t i;

	if (nb_flows <= 0)
		return NULL;
	/* Align to the next power of 2, 32bits integer is enough now. */
	if (!rte_is_power_of_2(nb_flows))
		nb_flows_aligned = rte_align32pow2(nb_flows);
	else
		nb_flows_aligned = nb_flows;
	/* double the flows to avoid collisions */
	nb_flows_aligned <<= 1;
	alloc_size = sizeof(struct simple_fwd_ft)
		+ sizeof(struct simple_fwd_ft_bucket) * nb_flows_aligned;
	DOCA_LOG_DBG("malloc size =%d", alloc_size);

	ft = malloc(alloc_size);
	if (ft == NULL) {
		DOCA_LOG_CRIT("no mem");
		return NULL;
	}
	memset(ft, 0, alloc_size);
	ft->cfg.entry_size = sizeof(struct simple_fwd_ft_entry)
		+ user_data_size;
	ft->cfg.user_data_size = user_data_size;
	ft->cfg.size = nb_flows_aligned;
	ft->cfg.mask = nb_flows_aligned - 1;
	ft->simple_fwd_aging_cb = simple_fwd_aging_cb;
	ft->simple_fwd_aging_hw_cb = simple_fwd_aging_hw_cb;

	DOCA_LOG_DBG("FT created: flows=%d, user_data_size=%d", nb_flows_aligned,
		     user_data_size);
	for (i = 0; i < ft->cfg.size; i++)
		rte_spinlock_init(&ft->buckets[i].lock);
	if (age_thread)
		simple_fwd_ft_aging_thread_start(ft);
	return ft;
}

static struct simple_fwd_ft_entry*
_simple_fwd_ft_find(struct simple_fwd_ft *ft,
		    struct simple_fwd_ft_key *key)
{
	uint32_t idx;
	struct simple_fwd_ft_entry_head *first;
	struct simple_fwd_ft_entry *node;

	idx = key->rss_hash & ft->cfg.mask;
	DOCA_LOG_DBG("looking for index%d", idx);
	first = &ft->buckets[idx].head;
	LIST_FOREACH(node, first, next) {
		if (simple_fwd_ft_key_equal(&node->key, key)) {
			simple_fwd_ft_update_expiration(node);
			return node;
		}
	}
	return NULL;
}

bool
simple_fwd_ft_find(struct simple_fwd_ft *ft,
		   struct simple_fwd_pkt_info *pinfo,
		   struct simple_fwd_ft_user_ctx **ctx)
{
	struct simple_fwd_ft_entry *fe;
	struct simple_fwd_ft_key key = {0};

	if (simple_fwd_ft_key_fill(pinfo, &key))
		return false;

	fe = _simple_fwd_ft_find(ft, &key);
	if (fe == NULL)
		return false;

	*ctx = &fe->user_ctx;
	return true;
}

bool
simple_fwd_ft_add_new(struct simple_fwd_ft *ft,
		      struct simple_fwd_pkt_info *pinfo,
		      struct simple_fwd_ft_user_ctx **ctx)
{
	int idx;
	struct simple_fwd_ft_key key = {0};
	struct simple_fwd_ft_entry *new_e;
	struct simple_fwd_ft_entry_head *first;

	if (!ft)
		return false;

	if (simple_fwd_ft_key_fill(pinfo, &key)) {
		DOCA_LOG_DBG("failed on key");
		return false;
	}

	new_e = malloc(ft->cfg.entry_size);
	if (new_e == NULL) {
		DOCA_LOG_WARN("oom");
		return false;
	}

	memset(new_e, 0, ft->cfg.entry_size);
	simple_fwd_ft_update_expiration(new_e);
	new_e->user_ctx.fid = ft->fid_ctr++;
	*ctx = &new_e->user_ctx;

	DOCA_LOG_DBG("defined new flow %llu",
		     (unsigned int long long)new_e->user_ctx.fid);
	memcpy(&new_e->key, &key, sizeof(struct simple_fwd_ft_key));
	idx = pinfo->rss_hash & ft->cfg.mask;
	new_e->buckets_index = idx;
	first = &ft->buckets[idx].head;

	rte_spinlock_lock(&ft->buckets[idx].lock);
	LIST_INSERT_HEAD(first, new_e, next);
	rte_spinlock_unlock(&ft->buckets[idx].lock);
	ft->stats.add++;
	return true;
}

void
simple_fwd_ft_destroy(struct simple_fwd_ft *ft)
{
	uint32_t i;
	struct simple_fwd_ft_entry_head *first;
	struct simple_fwd_ft_entry *node;

	ft->stop_aging_thread = true;
	for (i = 0; i < ft->cfg.size; i++) {
		first = &ft->buckets[i].head;
		node =  LIST_FIRST(first);
		while (node) {
			_ft_destroy_entry(ft, node);
			node = LIST_FIRST(first);
		}
	}
	free(ft);
}
