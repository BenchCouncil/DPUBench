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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

#include <rte_eal.h>

#include <doca_log.h>

#include "arg_parser.h"
#include "utils.h"

DOCA_LOG_REGISTER(ARGP);

/* DEFINES */
#define MAX_PROGRAM_NAME 32		/* Maximal length for program name  */
#define MAX_STRING_LEN 255		/* Maximal length for string in json file */
#define MAX_GENERAL_PARAMS_LEN 16	/* Maximal number for general params in general_params */
#define MAX_PARSER_PARAMS_LEN 16	/* Maximal number for program params in program_params */

#define MAX_DPDK_MISC_FLAGS_LEN 128	/* Maximal length for dpdk misc flags string */
#define DPDK_PARAM_LEN 64		/* Maximal length for dpdk flag format */
#define DPDK_PARAM_SIZE 20		/* Maximal number for dpdk flags on argv buffer */

#define MAX_JSON_MODE_ARGS 3		/* Command line length in json mode */

/* STRUCTS */
struct arg_parser_ctx {
	void *program_config;
	char program_name[MAX_PROGRAM_NAME];
	struct doca_program_type_config type_config;
	struct doca_program_general_config general_config;
	int general_params_size;	/* Current size of general params array */
	int program_params_size;	/* Current size of program params array */
};

/* GLOBAL_VARIABLES */
struct arg_parser_param general_params[MAX_GENERAL_PARAMS_LEN];
struct arg_parser_param program_params[MAX_PARSER_PARAMS_LEN];
struct arg_parser_ctx parser_ctx;

/* PARSER_HELPER_API */

/**
 * @brief print usage depends on params type
 *
 * @param params
 * array of flags
 * @param parmas_size
 * size of params.
 */
static void
usage_print(struct arg_parser_param *params, int params_size)
{
	int i, num_written = 0;
	bool has_short_flag = false;
	int cli_alignment_length = parser_ctx.type_config.is_grpc ? 42 : 32;

	for (i = 0; i < params_size; i++) {
		has_short_flag = false;
		num_written = printf("  ");
		if (params[i].short_flag != NULL) {
			num_written += printf("-%s", params[i].short_flag);
			has_short_flag = true;
		}
		if (params[i].long_flag != NULL) {
			if (has_short_flag)
				num_written += printf(", ");
			num_written += printf("--%s ", params[i].long_flag);
		}
		if (params[i].arguments != NULL)
			num_written += printf("%s ", params[i].arguments);
		if (num_written < cli_alignment_length)
			printf("%*s", cli_alignment_length - num_written, " ");
		printf("%s\n", params[i].description);
	}
}

void
arg_parser_usage(void)
{
	printf("\n\nUsage: doca_%s", parser_ctx.program_name);
	if (parser_ctx.type_config.is_dpdk)
		printf(" [DPDK Flags] --");
	if (parser_ctx.general_params_size != 0)
		printf(" [DOCA Flags]");
	if (parser_ctx.program_params_size != 0)
		printf(" [Program Flags]");
	printf("\n");

	if (parser_ctx.general_params_size != 0) {
		printf("\nDOCA Flags:\n");
		usage_print(general_params, parser_ctx.general_params_size);
	}
	if (parser_ctx.program_params_size != 0) {
		printf("\nProgram Flags:\n");
		usage_print(program_params, parser_ctx.program_params_size);
	}
	printf("\n\n");
	APP_EXIT("");
}

/* PARSER_HANDLE_JSON_FLOW_API */

/**
 * @brief Remove comments from json file.
 *
 * @param buffer
 * Buffer will contain function output ( what json file contain without comments )
 * @param size
 * Size of the buffer
 * @param json_fp
 * Pointer to the json file, use it to read the file.
 */
static void
delete_comments_from_json_file(char *buffer, size_t size, FILE *json_fp)
{
	char *ptr = buffer;
	int curr = fgetc(json_fp);
	int prev = ' ';

	while (curr != EOF && ptr < buffer + size) {
		if (prev == '/' && curr == '/') {
			while (curr != EOF && curr != '\n')
				curr = fgetc(json_fp);

			/* delete the first '/' in the buffer */
			ptr--;
		} else {
			*ptr = curr;
			ptr++;
			prev = curr;
			curr = fgetc(json_fp);
		}
	}
}

/**
 * @brief Create correct dpdk device format  (flag -a)
 *
 * @param buf
 * Output param
 * @param device
 * Device type (sf or regex);
 * @param id
 * Id of device, if sf it's sf number else regex it's port number
 * @param sft
 * Sft enable
 * @return
 * 0 in success, -1 otherwise.
 */
static int
create_dpdk_device_type(char *buf, const char *device, const char *id, bool sft_value, bool sft_en)
{
	int res;
	char *cur = buf;

	if (strcmp(device, "sf") == 0)
		res = snprintf(buf, DPDK_PARAM_LEN, "auxiliary:mlx5_core.sf.%s", id);
	else if (strcmp(device, "vf") == 0 || strcmp(device, "pf") == 0)
		res = snprintf(buf, DPDK_PARAM_LEN, "%s", id);
	else if (strcmp(device, "regex") == 0)
		res = snprintf(buf, DPDK_PARAM_LEN, "%s,class=regex", id);
	else {
		DOCA_LOG_ERR("Device \"%s\" is currently unsupported, please use the \"flags\" field for now.",
			device);
		return -1;
	}
	if (sft_en) {
		cur = buf + res;
		if (sft_value)
			res += snprintf(cur, DPDK_PARAM_LEN - res, ",sft_en=1");
		else
			res += snprintf(cur, DPDK_PARAM_LEN - res, ",sft_en=0");
	}
	if (res >= DPDK_PARAM_LEN) {
		DOCA_LOG_ERR("The value of \"%s\" refers to a %s ID that is longer than the limit (%d)",
			id, device, DPDK_PARAM_LEN-1);
		return -1;
	}
	return 0;
}

/**
 * @brief Extract DPDK (EAL) devices
 *
 * @param buffer
 * Output strings array contains DPDK flags
 * @param index
 * Output param, number of DPDK flags
 * @param devices
 * Json devices parsed data, use it to extract the DPDK devices
 * @return
 * 0 in success, -1 otherwise.
 */
static int
create_dpdk_devices(char buffer[DPDK_PARAM_SIZE][DPDK_PARAM_LEN], int *index,
		    struct json_object *devices)
{
	struct json_object *device;
	struct json_object *device_name, *device_id, *device_sft;
	const char *parsed_device_name = {0};
	const char *parsed_device_id = {0};
	bool parsed_stf_en = false, sft_en = false;
	int i, res, idx = *index;
	int n_devices = json_object_array_length(devices);

	for (i = 0; i < n_devices; i++) {
		device = json_object_array_get_idx(devices, i);
		if (device == NULL)
			return -1;

		/* pull device name */
		if (!json_object_object_get_ex(device, "device", &device_name))
			return -1;
		if (json_object_get_type(device_name) != json_type_string) {
			DOCA_LOG_ERR("Expecting a string value for \"device\"");
			return -1;
		}
		parsed_device_name = json_object_get_string(device_name);

		/* pull device id */
		if (!json_object_object_get_ex(device, "id", &device_id))
			return -1;
		if (json_object_get_type(device_id) != json_type_string) {
			DOCA_LOG_ERR("Expecting a string value for \"id\"");
			return -1;
		}
		parsed_device_id = json_object_get_string(device_id);

		/* pull sft enable */
		if (json_object_object_get_ex(device, "sft", &device_sft)) {
			if (json_object_get_type(device_sft) != json_type_boolean) {
				DOCA_LOG_ERR("Expecting a boolean value for \"sft\"");
				return -1;
			}
			parsed_stf_en = json_object_get_boolean(device_sft);
			sft_en = true;
		}

		/* add device to buffer */
		if (idx + 2 > DPDK_PARAM_SIZE) {
			DOCA_LOG_ERR("DPDK buffer is full");
			return -1;
		}
		memcpy(buffer[idx], "-a", strlen("-a"));
		idx++;
		res = create_dpdk_device_type(buffer[idx], parsed_device_name, parsed_device_id,
						parsed_stf_en, sft_en);
		if (res < 0)
			return res;
		idx++;
	}
	*index = idx;
	return 0;
}

/**
 * @brief Extract DOCA general flags
 *
 * @param parsed_json
 * Json parsed data
 * @param flags_name
 * General or Program flags
 * @param params
 * Array of flags
 * @param params_size
 * Array size
 * @param parsed_config
 * Configuration struct
 */
static void
handle_json_args(struct json_object *parsed_json, char *flags_name,
	struct arg_parser_param *params, int params_size, void *parsed_config)
{
	int param_index, num = 0;
	struct json_object *doca_flags, *doca_flag;
	bool enable = false;
	const char *temp = NULL;
	char str[MAX_STRING_LEN] = {0};

	if (!json_object_object_get_ex(parsed_json, flags_name, &doca_flags))
		return;
	for (param_index = 0; param_index < params_size; param_index++) {
		if (json_object_object_get_ex(doca_flags,
			params[param_index].long_flag, &doca_flag)){
			if (params[param_index].is_cli_only) {
				DOCA_LOG_WARN("Flag \"%s\" is only supported in the CLI",
					params[param_index].long_flag);
				continue;
			}
			switch (params[param_index].arg_type) {

			/* in case flag accept string argument */
			case ARG_PARSER_TYPE_STRING:
				if (json_object_get_type(doca_flag) != json_type_string) {
					DOCA_LOG_ERR("Expecting a string value for \"%s\"",
						params[param_index].long_flag);
					arg_parser_usage();
				}
				temp = json_object_get_string(doca_flag);
				if (strlen(temp) >= MAX_STRING_LEN) {
					DOCA_LOG_ERR("The value of \"%s\" is longer than the limit %d",
					params[param_index].long_flag, MAX_STRING_LEN);
					arg_parser_usage();
				}
				strcpy(str, temp);
				params[param_index].callback(parsed_config, (void *)str);
				break;

			/* in case flag accept integer argument */
			case ARG_PARSER_TYPE_INT:
				if (json_object_get_type(doca_flag) != json_type_int) {
					DOCA_LOG_ERR("Expecting a int value for \"%s\"",
						params[param_index].long_flag);
					arg_parser_usage();
				}
				num = json_object_get_int(doca_flag);
				params[param_index].callback(parsed_config, (void *)&num);
				break;

			/* in case flag accept boolean argument */
			case ARG_PARSER_TYPE_BOOLEAN:
				if (json_object_get_type(doca_flag) != json_type_boolean) {
					DOCA_LOG_ERR("Expecting a boolean value for \"%s\"",
						params[param_index].long_flag);
					arg_parser_usage();
				}
				enable = json_object_get_boolean(doca_flag);
				if (enable)
					params[param_index].callback(parsed_config, (void *)&enable);
				break;
			default:
				DOCA_LOG_ERR("Invalid arg_type: %s",
					     params[param_index].long_flag);
				arg_parser_usage();
				break;
			}
		} else {
			if (params[param_index].is_mandatory) {
				DOCA_LOG_ERR("Parameter \"%s\" is mandatory",
						params[param_index].long_flag);
				arg_parser_usage();
			}
		}
	}
}

static int
create_dpdk_core_flag(char buffer[DPDK_PARAM_SIZE][DPDK_PARAM_LEN], struct json_object *dpdk_flags,
	char *long_flag, char *short_flag, int *count, enum  json_type json_arg_type)
{
	struct json_object *core_flag;
	const char *core_string_param = NULL;
	int core_int_param;
	int index = *count;

	if (json_object_object_get_ex(dpdk_flags, long_flag, &core_flag)) {
		if (index + 2 > DPDK_PARAM_SIZE) {
			DOCA_LOG_ERR("DPDK buffer is full");
			return -1;
		}
		switch (json_arg_type) {
		case json_type_int:
			if (json_object_get_type(core_flag) != json_type_int) {
				DOCA_LOG_ERR("Expecting an integer value for \"%s\"", long_flag);
				return -1;
			}
			core_int_param = json_object_get_int(core_flag);
			sprintf(buffer[index], "%s", short_flag);
			index++;
			sprintf(buffer[index], "%d", core_int_param);
			index++;
			break;
		case json_type_string:
			if (json_object_get_type(core_flag) != json_type_string) {
				DOCA_LOG_ERR("Expecting an string value for \"%s\"", long_flag);
				return -1;
			}
			core_string_param = json_object_get_string(core_flag);
			sprintf(buffer[index], "%s", short_flag);
			index++;
			sprintf(buffer[index], "%s", core_string_param);
			index++;
			break;
		default:
			DOCA_LOG_ERR("%s: json type not supported", __func__);
			return -1;
		}
	}
	*count = index;
	return 0;
}

/**
 * @brief extract DPDK (EAL) flags from json file
 *
 * @param buffer
 * Output strings array contains DPDK flags
 * @param count
 * Output param, number of DPDK flags
 * @param parsed_json
 * Json parsed data, use it to extract the DPDK flags
 * @return
 * 0 on success, -1 otherwise.
 */
static int
create_dpdk_input_from_json(char buffer[DPDK_PARAM_SIZE][DPDK_PARAM_LEN], int *count,
				   struct json_object *parsed_json)
{
	struct json_object *dpdk_flags;
	struct json_object *devices;
	struct json_object *misc_flags;

	int res;
	char delim[] = " ";
	int index = 0;
	const char *parsed_misc_f = NULL;

	if (!json_object_object_get_ex(parsed_json, "doca_dpdk_flags", &dpdk_flags))
		return -1;

	/* flag -a -- create dpdk devices format */
	if (json_object_object_get_ex(dpdk_flags, "devices", &devices)) {
		if (create_dpdk_devices(buffer, &index, devices) < 0)
			return -1;
	}

	/* flag -c -- create core mask flag format */
	res = create_dpdk_core_flag(buffer, dpdk_flags, "core-mask", "-c", &index, json_type_int);
	if (res < 0)
		return res;

	/* flag -l -- create core list flag format */
	res = create_dpdk_core_flag(buffer, dpdk_flags, "core-list", "-l", &index,
		json_type_string);
	if (res < 0)
		return res;

	/* in case misc flags added to json file, create the suitable format */
	if (json_object_object_get_ex(dpdk_flags, "flags", &misc_flags)) {
		if (json_object_get_type(misc_flags) != json_type_string) {
			DOCA_LOG_DBG("Expecting a string value for \"flags\"");
			return -1;
		}
		char misc_flags_str[MAX_DPDK_MISC_FLAGS_LEN] = {0};

		parsed_misc_f = json_object_get_string(misc_flags);
		if (strlen(parsed_misc_f) >= MAX_DPDK_MISC_FLAGS_LEN) {
			DOCA_LOG_DBG("The value of \"flags\" is longer than the limit (%d)",
			MAX_DPDK_MISC_FLAGS_LEN);
			return -1;
		}
		strcpy(misc_flags_str, parsed_misc_f);

		if (strlen(misc_flags_str) != 0) {
			char *ptr = strtok(misc_flags_str, delim);

			while (ptr != NULL) {
				if (strlen(ptr) >= DPDK_PARAM_LEN) {
					DOCA_LOG_ERR("Misc flag is longer than the limit (%d)",
						DPDK_PARAM_LEN);
					return -1;
				}
				if (index >= DPDK_PARAM_SIZE) {
					DOCA_LOG_ERR("DPDK buffer is full");
					return -1;
				}
				strcpy(buffer[index], ptr);
				index++;
				ptr = strtok(NULL, delim);
			}
		}
	}
	*count = index;
	return 0;
}

/**
 * @brief dynamic allocation for json data buffer
 *
 * In this function creating dpdk, program and DOCA general params with correct format
 * by extract data from the json file.
 *
 * @param fp
 * Pointer to json file.
 * @param file_length
 * Output param, length of the json data buffer.
 * @param json_data
 * allocation place
 */
static int
allocate_json_buffer_dynamic(FILE *fp, size_t *file_length, char **json_data)
{
	ssize_t buf_len = 0;

	/* use fseek to put file counter to the end, and calculate file length */
	if (fseek(fp, 0L, SEEK_END) == 0) {
		buf_len = ftell(fp);
		if (buf_len < 0) {
			DOCA_LOG_ERR("ftell() function failed");
			return -1;
		}

		/* dynamic allocation */
		*json_data = (char *)calloc((buf_len + 1), sizeof(char));
		if (*json_data == NULL) {
			DOCA_LOG_ERR("malloc() function failed");
			return -1;
		}

		/* return file counter to the beginning */
		if (fseek(fp, 0L, SEEK_SET) != 0) {
			free(*json_data);
			*json_data = NULL;
			DOCA_LOG_ERR("fseek() function failed");
			return -1;
		}
	}
	*file_length = buf_len;
	return 0;
}

/**
 * @brief Prepare dpdk init param and call eal init for json flow.
 *
 * @param buffer
 * Extracted flag from json file
 * @param program_path
 * path of bin command
 */
static void
json_dpdk_eal_init(char buffer[DPDK_PARAM_SIZE][DPDK_PARAM_LEN], char *program_path, int argc)
{
	int i, ret;
	char *argv[DPDK_PARAM_SIZE] = {0};

	argv[0] = program_path;
	for (i = 1; i <= argc; i++)
		argv[i] = &buffer[i - 1][0];
	argv[argc + 1] = "--";
	ret = rte_eal_init(argc + 2, argv);
	if (ret < 0)
		APP_EXIT("EAL initialization failed");
}

/**
 * @brief Main function for json mode.
 *
 * In this function creating dpdk, program and DOCA general params with correct format
 * by extract data from the json file.
 *
 * @param program_path
 * path of bin command
 * @param json_file_path
 * Path to json file.
 */
static void
handle_json_arguments(char *program_path, char *json_file_path)
{
	char buffer[DPDK_PARAM_SIZE][DPDK_PARAM_LEN];
	char *json_data =  NULL;
	int argc = 0;
	size_t file_length = 0;
	int res = 0;
	FILE *json_fp;
	struct json_object *parsed_json;

	/* open and read JSON file */
	memset(buffer, 0, sizeof(buffer));
	json_fp = fopen(json_file_path, "r");
	if (json_fp == NULL)
		APP_EXIT("Failed to open json file: \"%s\"", json_file_path);

	/* dynamic allocate for json data buffer */
	res = allocate_json_buffer_dynamic(json_fp, &file_length, &json_data);
	if (res < 0) {
		fclose(json_fp);
		APP_EXIT("Failed to allocate data buffer for the json file");
	}

	/* remove comments from json data */
	delete_comments_from_json_file(json_data, file_length, json_fp);
	parsed_json = json_tokener_parse(json_data);

	fclose(json_fp);
	free(json_data);
	json_data = NULL;

	/* create dpdk params and call dpdk init*/
	if (parser_ctx.type_config.is_dpdk) {
		if (create_dpdk_input_from_json(buffer, &argc, parsed_json) < 0)
			APP_EXIT("Failed to parse the DPDK parameters");
		json_dpdk_eal_init(buffer, program_path, argc);
	}

	/* create general and program params */
	handle_json_args(parsed_json, "doca_general_flags", general_params,
		parser_ctx.general_params_size, &parser_ctx.general_config);
	handle_json_args(parsed_json, "doca_program_flags", program_params,
		parser_ctx.program_params_size, parser_ctx.program_config);
	json_object_put(parsed_json);
}

/* PARSER_HANDLE_REGULAR_FLOW_API */

/**
 * @brief passing dpdk flags by call rte_eal_init function
 */
static void
cli_dpdk_eal_init(int *argc, char **argv[])
{
	int ret = 0;

	/* Initialize the Environment Abstraction Layer (EAL) */
	ret = rte_eal_init(*argc, *argv);
	if (ret < 0)
		APP_EXIT("EAL initialization failed");
	*argc -= ret;
	*argv += ret;
}

/**
 * @brief check if there is a match, and return match value.
 *
 * @param param_name
 * Output pointer put match string there
 * @param param
 * current param
 * @param flag
 * Current flag on argv
 */
static bool
check_param_match(char **param_name, struct arg_parser_param *param, char *flag)
{
	*param_name = NULL;

	/* check short name match, short flag on cli appears with '-' so we have to ignore it */
	if (param->short_flag != NULL && strcmp(param->short_flag, flag + 1) == 0) {
		*param_name = param->short_flag;
		return true;
	}

	/* check long name match, long flag on cli appears with "--" so we have to ignore them */
	if (param->long_flag != NULL && strcmp(param->long_flag, flag + 2) == 0) {
		*param_name = param->long_flag;
		return true;
	}
	return false;
}

/**
 * @brief Extract general or program params from command line interface
 *
 * @param params
 * Parameteres array for general or program params
 * @param params_size
 * Param array size
 * @param parsed_config
 * Configuration struct to store the parsed flags
 */
static void
parse_cli_args(int argc, char **argv, struct arg_parser_param *params, int params_size,
				void *parsed_config)
{
	int flag_i, param_i, value;
	char *p_name, *param_name = NULL;
	bool flag, match = false;

	for (param_i = 0; param_i < params_size; param_i++) {
		match = false;
		for (flag_i = 1; flag_i < argc && !match; flag_i++) {
			if (check_param_match(&param_name, &params[param_i], argv[flag_i])) {
				match = true;
				switch (params[param_i].arg_type) {
				case ARG_PARSER_TYPE_STRING:
					if (flag_i + 1 == argc) {
						DOCA_LOG_ERR("Missing value for parameter \"%s\"", param_name);
						arg_parser_usage();
					}
					params[param_i].callback(parsed_config, argv[flag_i + 1]);
					break;
				case ARG_PARSER_TYPE_INT:
					if (flag_i + 1 == argc) {
						DOCA_LOG_ERR("Missing value for parameter \"%s\"", param_name);
						arg_parser_usage();
					}
					value = atoi(argv[flag_i + 1]);
					params[param_i].callback(parsed_config, &value);
					break;
				case ARG_PARSER_TYPE_BOOLEAN:
					flag = true;
					params[param_i].callback(parsed_config, &flag);
					break;
				default:
					DOCA_LOG_ERR("Invalid arg_type for parameter: %s", param_name);
					arg_parser_usage();
					break;
				}
			}
		}
		p_name = (params[param_i].long_flag != NULL) ?
		params[param_i].long_flag : params[param_i].short_flag;
		if (params[param_i].is_mandatory && !match) {
			DOCA_LOG_ERR("Parameter \"%s\" is mandatory", p_name);
			arg_parser_usage();
		}
	}
}

/**
 * @brief main function for regular command line mode
 *
 * In this function call dpdk init and update the flags.
 *
 * @param argc
 * Argv size
 * @param argv
 * Command line params
 */
static void
handle_cli_arguments(int argc, char **argv)
{
	if (parser_ctx.type_config.is_dpdk)
		cli_dpdk_eal_init(&argc, &argv);

	/* cli_dpdk_eal_init update the argc and argv depend on number of flags dpdk had read */
	if (argc >= 1) {
		parse_cli_args(argc, argv, general_params, parser_ctx.general_params_size,
					&parser_ctx.general_config);
		parse_cli_args(argc, argv, program_params, parser_ctx.program_params_size,
					parser_ctx.program_config);
	}
}

/**
 * @brief register general (DOCA) flag
 *
 * @param input_param
 * Contains param details
 */
static void
register_general_param(struct arg_parser_param *input_param)
{
	if (parser_ctx.general_params_size >= MAX_GENERAL_PARAMS_LEN) {
		DOCA_LOG_ERR("Too many general params were registered, limit is %d",
			MAX_GENERAL_PARAMS_LEN);
		arg_parser_usage();
	}
	memcpy(&general_params[parser_ctx.general_params_size], input_param, sizeof(*input_param));
	parser_ctx.general_params_size++;
}

static void
log_level_callback(void *doca_config, void *param)
{
	struct doca_program_general_config *program_config = (struct doca_program_general_config *) doca_config;

	program_config->log_level = *(int *) param;
	doca_log_global_level_set(*(int *) param);
}

static void
grpc_callback(void *doca_config, void *param)
{
	struct doca_program_general_config *program_config = (struct doca_program_general_config *) doca_config;
	char *address = (char *) param;

	if (strlen(address) >= MAX_SERVER_ADDRESS) {
		DOCA_LOG_ERR("gRPC Server address length greater than limit (%d)",
			MAX_SERVER_ADDRESS);
		return;
	}
	strcpy(program_config->grpc_address, address);
}

static void
help_callback(void *doca_config, void *param)
{
	arg_parser_usage();
}

static void
register_general_params()
{
	struct arg_parser_param help_param = {
		.short_flag = "h",
		.long_flag = "help",
		.arguments = NULL,
		.description = "Print a help synopsis",
		.callback = help_callback,
		.arg_type = ARG_PARSER_TYPE_BOOLEAN,
		.is_mandatory = false,
		.is_cli_only = true
	};
	struct arg_parser_param log_level_param = {
		.short_flag = "l",
		.long_flag = "log-level",
		.arguments = NULL,
		.description = "Set the log level for the program <CRITICAL=0, DEBUG=4>",
		.callback = log_level_callback,
		.arg_type = ARG_PARSER_TYPE_INT,
		.is_mandatory = false,
		.is_cli_only = false
	};
	struct arg_parser_param grpc_param = {
		.short_flag = NULL,
		.long_flag = "grpc-address",
		.arguments = "ip_address[:port]",
		.description = "Set the IP address for the grpc server",
		.callback = grpc_callback,
		.arg_type = ARG_PARSER_TYPE_STRING,
		.is_mandatory = true,
		.is_cli_only = false
	};

	register_general_param(&help_param);
	register_general_param(&log_level_param);

	if (parser_ctx.type_config.is_grpc)
		register_general_param(&grpc_param);
}

/* PARSER_API */

void
arg_parser_init(const char *program_name, struct doca_program_type_config *type_config,
		void *program_config)
{
	if (strlen(program_name) >= MAX_PROGRAM_NAME)
		APP_EXIT("Program name is longer than limit (%d)", MAX_PROGRAM_NAME);
	strcpy(parser_ctx.program_name, program_name);
	parser_ctx.program_config = program_config;
	parser_ctx.type_config.is_dpdk = type_config->is_dpdk;
	parser_ctx.type_config.is_grpc = type_config->is_grpc;
	parser_ctx.general_config.log_level = doca_log_global_level_get();
	memset(parser_ctx.general_config.grpc_address, 0, MAX_SERVER_ADDRESS);
	parser_ctx.program_params_size = 0;
	parser_ctx.general_params_size = 0;

	register_general_params();
}

void
arg_parser_register_param(struct arg_parser_param *input_param)
{
	if (parser_ctx.program_params_size >= MAX_PARSER_PARAMS_LEN) {
		DOCA_LOG_ERR("Too many parameters registered, limit is %d", MAX_PARSER_PARAMS_LEN);
		arg_parser_usage();
	}

	/* param don't have long flag(JSON KEY), so supported on cli only */
	if (input_param->long_flag == NULL)
		input_param->is_cli_only = true;

	/* add param to params array */
	memcpy(&program_params[parser_ctx.program_params_size], input_param, sizeof(*input_param));
	parser_ctx.program_params_size++;
}

void
arg_parser_start(int argc, char **argv, struct doca_program_general_config **general_config)
{
	*general_config = &parser_ctx.general_config;
	if (argc > 1 &&
	    ((strcmp(argv[1], "--json")) == 0 || (strcmp(argv[1], "-j")) == 0)) { /* json mode */
		if (argc == MAX_JSON_MODE_ARGS) {
			handle_json_arguments(argv[0], argv[2]);
		} else {
			DOCA_LOG_ERR("Json mode was invoked with incorrect number of arguments");
			arg_parser_usage();
		}

	} else { /* command line mode */
		if (parser_ctx.type_config.is_dpdk) {
			if (argc == 3 && !strcmp(argv[1], "--") &&
				(!strcmp(argv[2], "-h") || !strcmp(argv[2], "--help")))
				arg_parser_usage();
		}

		handle_cli_arguments(argc, argv);
	}
}

void
arg_parser_destroy()
{
	int ret;

	if (parser_ctx.type_config.is_dpdk) {
		ret = rte_eal_cleanup();
		if (ret < 0)
			APP_EXIT("rte eal cleanup failed, error=%d", ret);
	}
}
