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

#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SERVER_ADDRESS 24
typedef void (*callback_func)(void *, void *);

enum arg_parser_type {
	ARG_PARSER_TYPE_STRING = 0,
	ARG_PARSER_TYPE_INT,
	ARG_PARSER_TYPE_BOOLEAN,
};

struct doca_program_general_config {
	int log_level;
	char grpc_address[MAX_SERVER_ADDRESS];
};

struct doca_program_type_config {
	bool is_dpdk;
	bool is_grpc;
};

struct arg_parser_param {
	char *short_flag;
	char *long_flag;
	char *arguments;
	char *description;
	callback_func callback;
	enum arg_parser_type arg_type;
	bool is_mandatory;
	bool is_cli_only;
};

/**
 * @brief print usage instructions and exit.
 */
void arg_parser_usage(void);

/**
 * @brief init parser interface.
 *
 * @param program_name
 * Name of current program, using the name for log prints.
 * @param type_config
 * Announce if current program is DPDK/gRPC based.
 * @param program_config
 * Pointer to the program configuration struct
 */
void
arg_parser_init(const char *program_name, struct doca_program_type_config *type_config,
		void *program_config);

/**
 * @brief register a program flag.
 *
 * @note: value of is_cli_only field may be changed in this function.
 *
 * @param input_param
 * Contains input flag definitions.
 */
void arg_parser_register_param(struct arg_parser_param *input_param);

/**
 * @brief parse incoming arguments (cmd line/json).
 *
 * @note: if the application is DPDK app, arg_parser_start() will parses DPDK flags
 * and calling rte_eal_init().
 *
 * @param general_config
 * DOCA wide input arguments (log_level, ...).
 */
void
arg_parser_start(int argc, char **argv, struct doca_program_general_config **general_config);

/**
 * @brief ARG Parser destroy, cleanup all resources include calling rte_eal_cleanup(),
 * to release EAL resources that has allocated during rte_eal_init().
 */
void arg_parser_destroy(void);

#ifdef __cplusplus
}
#endif

#endif
