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

#ifndef SIG_DB_H
#define SIG_DB_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>


#ifdef __cplusplus
extern "C" {
#endif

bool sig_db_sig_info_get_block_status(uint32_t sig_id);

void sig_db_sig_info_set_block_status(uint32_t sig_id, bool block);

void sig_db_sig_info_fids_inc(uint32_t sig_id);

void sig_db_sig_info_set(uint32_t sig_id, char *app_name);

struct sig_info *sig_db_sig_info_get(uint32_t sig_id);

void sig_db_sig_info_create(uint32_t sig_id, char *app_name);

void sig_db_init(void);

void sig_db_destroy(void);

int sig_database_write_to_csv(void *csv_filename);

#ifdef __cplusplus
}
#endif

#endif
