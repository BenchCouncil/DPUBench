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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "doca_netflow.h"
#include "doca_log.h"
#include "arg_parser.h"

#define NUM_RECORDS 40
DOCA_LOG_REGISTER(NETFLOW);

/*
 * Make a dummy netflow record and send it 40 times to the netflow collector
 * Note that this example use the default template
 */
int default_template_example(void)
{
	struct doca_netflow_default_record *records[NUM_RECORDS];
	const struct doca_netflow_template *template;
	int i, err;
	int ret;
	int records_sent = 0;
	struct in6_addr src_addr_v6, dst_addr_v6, next_hop_v6;
	/* Creating dummy record */
	inet_pton(AF_INET6, "0:0:0:0:0:FFFF:C0A8:7801", &src_addr_v6);
	inet_pton(AF_INET6, "0:0:0:0:0:FFFF:C0A8:7802", &dst_addr_v6);
	inet_pton(AF_INET6, "0:0:0:0:0:FFFF:C0A8:8507", &next_hop_v6);
	struct doca_netflow_default_record record = {
	    .src_addr_v4 = inet_addr("192.168.120.1"),		/* Source IPV4 Address */
	    .dst_addr_v4 = inet_addr("192.168.120.2"),		/* Destination IPV4 Address */
	    .src_addr_v6 = src_addr_v6,						/* Source IPV6 Address */
	    .dst_addr_v6 = dst_addr_v6,						/* Destination IPV6 Address */
	    .next_hop_v4 = inet_addr("192.168.133.7"),		/* Next hop router's IPV4 Address */
	    .next_hop_v6 = next_hop_v6,						/* Next hop router's IPV6 Address */
	    .input = htobe16(1),							/* Input interface index */
	    .output = htobe16(65535),						/* Output interface index */
	    .src_port = htobe16(5353),						/* TCP/UDP source port number or equivalent */
	    .dst_port = htobe16(8000),						/* TCP/UDP destination port number or equivalent */
	    .tcp_flags = 0,									/* Cumulative OR of tcp flags */
	    .protocol = 17,									/* IP protocol type (for example, TCP  = 6 = , UDP  = 17) */
	    .tos = 0,										/* IP Type-of-Service */
	    .src_as = htobe16(0),							/* originating AS of source address */
	    .dst_as = htobe16(0),							/* originating AS of destination address */
	    .src_mask = 0,									/* source address prefix mask bits */
	    .dst_mask = 0,									/* destination address prefix mask bits */
	    .d_pkts = htobe32(9),							/* Packets sent in Duration */
	    .d_octets = htobe32(1909),						/* Octets sent in Duration. */
	    .first = htobe32(800294),						/* SysUptime at start of flow */
	    .last = htobe32(804839),						/* and of last packet of flow */
	    .flow_id = htobe64(1337),						/* This identifies a transaction within a connection */
	    .application_name = "NETFLOW EXAMPLE"			/* Name associated with a classification */
	};

	/* Duplicating the record for example purposes, forming an array of records to send */
	for (i = 0; i < NUM_RECORDS; i++)
		records[i] = &record;
	/* Get default template */
	template = doca_netflow_template_default_get();
	if (template == NULL)
		return -1;

	/*
	 * Init the exporter
	 * IF the path is set to NULL then the default location is used
	 * Default location is specified in DOCA_NETFLOW_CONF_DEFAULT_PATH
	 * Replace the NULL to the configuration file location
	 */
	ret = doca_netflow_exporter_init(NULL);
	if (ret < 0) {
		DOCA_LOG_ERR("init failed, check conf file");
		return ret;
	}

	/*
	 * Sending the record array
	 * The while loop ensure that all records have been sent, in case just some sent
	 * This section should happan periodically with updated flows
	 */
	while (records_sent < NUM_RECORDS) {
		ret =
		    doca_netflow_exporter_send(template, (const void **)(records + records_sent),
					       NUM_RECORDS - records_sent, &err);
		if (!ret) {
			DOCA_LOG_ERR("Error, failed to send netflow msg, err =%d", err);
			doca_netflow_exporter_destroy();
			return ret;
		}
		records_sent += ret;
	}

	/* Clean up and exit */
	doca_netflow_exporter_destroy();
	DOCA_LOG_INFO("Successfully sent %d netflow records with default template.", NUM_RECORDS);
	return 0;
}

/*
 * Make a dummy netflow record and send it 40 times to the netflow collector
 * This example create a custom template, use only 5 fields
 * (full list can be found in doca_netflow_types.h)
 */
int custom_template_example(void)
{
	/* Declare the struct for the custom template */
	struct doca_netflow_custom_record {
		uint32_t src_addr_v4;	/**< Source IP Address */
		uint32_t dst_addr_v4;	/**< Destination IP Address */
		uint16_t src_port;	/**< TCP/UDP source port number or equivalent */
		uint16_t dst_port;	/**< TCP/UDP destination port number or equivalent */
		uint8_t protocol;	/**< IP protocol type (for example, TCP = 6; UDP = 17) */
	} __attribute__((packed));
	struct doca_netflow_custom_record *records[NUM_RECORDS];
	int i, err;
	int ret;
	int records_sent = 0;
	/* Creating a custom template */
	struct doca_netflow_flowset_field fields[] = {
		{.type = DOCA_NETFLOW_IPV4_SRC_ADDR, .length = DOCA_NETFLOW_IPV4_SRC_ADDR_DEFAULT_LENGTH},
		{.type = DOCA_NETFLOW_IPV4_DST_ADDR, .length = DOCA_NETFLOW_IPV4_DST_ADDR_DEFAULT_LENGTH},
		{.type = DOCA_NETFLOW_L4_SRC_PORT, .length = DOCA_NETFLOW_L4_SRC_PORT_DEFAULT_LENGTH},
		{.type = DOCA_NETFLOW_L4_DST_PORT, .length = DOCA_NETFLOW_L4_DST_PORT_DEFAULT_LENGTH},
		{.type = DOCA_NETFLOW_PROTOCOL, .length = DOCA_NETFLOW_PROTOCOL_DEFAULT_LENGTH}
	};
	struct doca_netflow_template template = {
		.field_count = 5,
		.fields = fields
	};
	/* Creating dummy record */
	struct doca_netflow_custom_record record = {
	    .src_addr_v4 = inet_addr("192.168.120.1"),	/* Source IP Address */
	    .dst_addr_v4 = inet_addr("192.168.120.2"),	/* Destination IP Address */
	    .src_port = htobe16(5353),	/* TCP/UDP source port number or equivalent */
	    .dst_port = htobe16(8000),	/* TCP/UDP destination port number or equivalent */
	    .protocol = 17,				/*IP protocol type (for example, TCP  = 6 = , UDP  = 17)*/
	};

	/* Duplicating the record for example purposes, forming an array of records to send */
	for (i = 0; i < NUM_RECORDS; i++)
		records[i] = &record;

	/*
	 * Init the exporter
	 * IF the path is set to NULL then the default location is used
	 * Default location is specified in DOCA_NETFLOW_CONF_DEFAULT_PATH
	 * Replace the NULL to the configuration file location
	 */
	ret = doca_netflow_exporter_init(NULL);
	if (ret < 0) {
		DOCA_LOG_ERR("init failed, check conf file");
		return ret;
	}

	/*
	 * Sending the record array
	 * The while loop ensure that all records have been sent, in case just some sent
	 * This section should happan periodically with updated flows
	 */
	while (records_sent < NUM_RECORDS) {
		ret =
		    doca_netflow_exporter_send(&template, (const void **)(records + records_sent),
					       NUM_RECORDS - records_sent, &err);
		if (ret < 0) {
			DOCA_LOG_ERR("Error, failed to send netflow msg, err =%d", err);
			doca_netflow_exporter_destroy();
			return ret;
		}
		records_sent += ret;
	}

	/* Clean up and exit */
	doca_netflow_exporter_destroy();
	DOCA_LOG_INFO("Successfully sent %d netflow records with default template.", NUM_RECORDS);
	return 0;
}

int main(int argc, char **argv)
{
	int ret;

	DOCA_LOG_INFO("start sending records...");
	/* Calling default template, can change to custom template function */

	/* init and start parsing */
	struct doca_program_general_config *doca_general_config;
	struct doca_program_type_config type_config = {
		.is_dpdk = false,
		.is_grpc = false,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("netflow", &type_config, NULL);
	arg_parser_start(argc, argv, &doca_general_config);
	ret = default_template_example();
	arg_parser_destroy();
	return ret;
}
