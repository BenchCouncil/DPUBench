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


#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <doca_log.h>
#include <doca_telemetry.h>

#include "telemetry_client.h"

#define SIZE 5
#define MAX_EXAMPLE_STRING_SIZE 256

DOCA_LOG_REGISTER(TELEMETRY);

static char *example_strings[SIZE] = {
	"example_str_1",
	"example_str_2",
	"example_str_3",
	"example_str_4",
	"example_str_5"
};

static int collected_example_events_global_count;

/* Event struct from which report will be serialized */
struct test_event_type {
	doca_telemetry_timestamp_t  timestamp;
	int32_t                     event_number;
	int32_t                     iter_num;
	uint64_t                    string_number;
	char                        example_string[MAX_EXAMPLE_STRING_SIZE];
} __packed;

/* Event type for schema. Should be consistent with event struct. */
static doca_telemetry_field_info_t example_fields[] = {
	{ "timestamp",      "Event timestamp",  DOCA_TELEMETRY_FIELD_TYPE_TIMESTAMP, 1 },
	{ "event_number",   "Event number",     DOCA_TELEMETRY_FIELD_TYPE_INT32,     1 },
	{ "iter_num",       "Iteration number", DOCA_TELEMETRY_FIELD_TYPE_INT32,     1 },
	{ "string_number",  "String number",    DOCA_TELEMETRY_FIELD_TYPE_UINT64,    1 },
	{ "example_string", "String example",   DOCA_TELEMETRY_FIELD_TYPE_CHAR,
								MAX_EXAMPLE_STRING_SIZE},
};

/*
 * This function fills up event buffer with the example string of specified number.
 * It also saves number of iteration, number of string and overall number of events.
 */
static void
prepare_example_event(struct test_event_type *ev1, int iter_num, int string_number)
{
	ev1->timestamp     = doca_telemetry_timestamp_get();
	ev1->event_number  = collected_example_events_global_count++;
	ev1->iter_num      = iter_num;
	ev1->string_number = string_number;
	strncpy(ev1->example_string, example_strings[string_number], MAX_EXAMPLE_STRING_SIZE - 1);
}

int
telemetry_config(void)
{
	int ret = 0;
	int k = 0;
	int i = 0;
	void *doca_schema = NULL;
	void *source = NULL;
	struct test_event_type test_event;
	doca_telemetry_type_index_t example_index;

	collected_example_events_global_count = 0;

	/* ======================== SCHEMA ATTRIBUTES =========================== */
	/* Set buffer size in bytes to fit 5 example events. By default it is set to 60K.
	 * Data root should be set to keep data schemas and binary data if file_write
	 * is enabled.
	 */
	struct doca_telemetry_buffer_attr_t buffer = { .buffer_size = sizeof(test_event) * 5,
						       .data_root = "./telemetry_example_data" };

	/* Enable file write during the app development.
	 * Check written files under data root to make sure that data format is correct.
	 * Default max_file_size is 1 Mb, default max_file_age is 1 hour.
	 */
	struct doca_telemetry_file_write_attr_t file_write =  {	.max_file_size = 1 * 1024 * 1024,
								.max_file_age = 60 * 60 * 1000000L,
								.file_write_enabled = true};

	/* If ipc is enabled, doca telemetry will try to find Telemetry Service socket
	 * under ipc_sockets_dir. IPC is disabled by default.
	 */
	struct doca_telemetry_ipc_attr_t ipc = { .ipc_enabled = 0,
		.ipc_sockets_dir = "/opt/mellanox/doca/services/telemetry/ipc_sockets"};

	/* Optionally change parameters for IPC connection/reconnection tries
	 * and IPC socket timeout. Default values are 100 msec, 3 tries, and 500 ms accordingly.
	 */
	struct doca_telemetry_ipc_timeout_attr_t
	ipc_timeouts = { .ipc_max_reconnect_time_msec = 100,
			 .ipc_max_reconnect_tries     = 3,
			 .ipc_socket_timeout_msec     = 500};

	/* =============================== SCHEMA =============================== */
	/* 1. Init DOCA schema */
	doca_schema = doca_telemetry_schema_init("example_doca_schema_name");
	if (doca_schema == NULL) {
		DOCA_LOG_ERR("cannot init doca schema");
		return 1;
	}

	/* 2. Apply attributes */
	doca_telemetry_schema_buffer_attr_set(doca_schema, &buffer);
	doca_telemetry_schema_file_write_attr_set(doca_schema, &file_write);
	doca_telemetry_schema_ipc_attr_set(doca_schema, &ipc);
	doca_telemetry_schema_ipc_timeouts_attr_set(doca_schema, &ipc_timeouts);

	/* 3. Add schema types */
	ret = doca_telemetry_schema_add_type(doca_schema, "example_event", example_fields,
					     NUM_OF_DOCA_FIELDS(example_fields), &example_index);
	if (ret != 0) {
		DOCA_LOG_ERR("cannot add type to doca_schema!");
		goto err_schema;
	}
	/* 4. "apply" schema */
	ret = doca_telemetry_schema_start(doca_schema);
	if (ret != 0) {
		DOCA_LOG_ERR("cannot start doca_schema!");
		goto err_schema;
	}

	/* =========================== SCHEMA END =============================== */


	/* ======================Create Telemetry source ======================== */

	/* 1. Create DOCA Telemetry Source context from DOCA schema */
	source = doca_telemetry_source_create(doca_schema);
	if (source == NULL) {
		DOCA_LOG_ERR("cannot create doca_source!");
		goto err_schema;
	}

	/* 2. Set source id and tag */
	struct doca_telemetry_source_name_attr_t source_attr = { .source_id  = "source_1",
								 .source_tag = "source_1_tag" };

	doca_telemetry_source_name_attr_set(source, &source_attr);

	/* 3. Start source to apply attributes and start services */
	ret = doca_telemetry_source_start(source);
	if (ret != 0) {
		DOCA_LOG_ERR("cannot start doca_source!");
		goto err_source;
	}
	/* 4*. Create more DOCA Sources if needed. */

	/* 5. Prepare events and report them via DOCA Telemetry */
	for (k = 0; k < 10; k++) {
		for (i = 0; i < SIZE; i++) {
			DOCA_LOG_INFO("progressing: k=%d \t i=%d", k, i);
			prepare_example_event(&test_event, k, i);
			if (doca_telemetry_source_report(source, example_index,
							 &test_event, 1) != 0) {
				DOCA_LOG_ERR("cannot report to doca_source!");
				goto err_source;
			}
		}
		if (k % 2 == 0) {
			/*
			 * Optionally force DOCA source buffer to flush.
			 * Handy for bursty events or specific event types.
			 */
			doca_telemetry_source_flush(source);
		}
	}

	/* Destroy all DOCA sources and DOCA schema to clean up */
	doca_telemetry_source_destroy(source);
	doca_telemetry_schema_destroy(doca_schema);

	return 0;
err_schema:
	doca_telemetry_schema_destroy(doca_schema);
	return 1;
err_source:
	doca_telemetry_source_destroy(source);
	doca_telemetry_schema_destroy(doca_schema);
	return 1;
}
