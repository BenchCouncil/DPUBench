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

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include <doca_log.h>

#include <flow_offload.h>
#include <grpc/log_forwarder.h>
#include <utils.h>
#include <arg_parser.h>

#include "dns_filter_core.h"
#include "orchestration.h"
#include "server.h"

DOCA_LOG_REGISTER(DNS_FILTER::GRPC);

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::Status;

/* Boolean for ending the server */
static std::condition_variable server_lock;

/* Clients management vars */
static struct synchronized_queue log_records_queue;
static struct clients_pool subscribed_clients;

/* Function used for inserting the log messages to the messages queue */
static void
flush_buffer(char *buffer)
{
	/* Insert log message to queue */
	synchronized_queue_enqueue(&log_records_queue, std::string(buffer));
}

static void
server_teardown()
{
	teardown_server_sessions(&log_records_queue, &subscribed_clients);
	server_lock.notify_one();
}

Status
DNSFilterImpl::Subscribe(ServerContext *context, const ::SubscribeReq *request,
			 ServerWriter<::LogRecord> *writer)
{
	(void)context;
	(void)request;

	if (!subscribe_client(&subscribed_clients, writer))
		return Status::CANCELLED;

	return Status::OK;
}

Status
DocaOrchestrationImpl::HealthCheck(ServerContext *context, const ::HealthCheckReq *request,
				   ::HealthCheckResp *response)
{
	(void)context;
	(void)request;
	(void)response;

	/* Show the service that we are responsive */
	return Status::OK;
}

Status
DocaOrchestrationImpl::Destroy(ServerContext *context, const ::DestroyReq *request,
			       ::DestroyResp *response)
{
	(void)context;
	(void)request;
	(void)response;

	server_teardown();

	return Status::OK;
}

static void
run_server(const char *arg)
{
	/* Check if we got a port or if we are using the default one */
	std::string server_address(arg);
	if (server_address.find(':') == std::string::npos)
		server_address += ":" + std::to_string(eNetworkPort::k_DnsFilter);

	/* Make sure the stream won't close on us and shorten delays */
	grpc::EnableDefaultHealthCheckService(true);

	/* Config the gRPC server */
	ServerBuilder builder;
	builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

	/* Add the services */
	DNSFilterImpl app_service;
	DocaOrchestrationImpl orchestration_service;
	builder.RegisterService(&app_service);
	builder.RegisterService(&orchestration_service);

	/* Start the logger thread */
	std::thread logger_thread([]{forward_log_records(&log_records_queue, &subscribed_clients);});

	/* Start the gRPC server */
	std::unique_ptr<Server> server(builder.BuildAndStart());
	DOCA_LOG_INFO("gRPC server started");

	/* Wait for the Destroy command */
	std::mutex mutex;
	std::unique_lock<std::mutex> lock(mutex);
	server_lock.wait(lock);

	/* Officially shut down the server */
	server->Shutdown();
	logger_thread.join();
}

/*
 *  The main function, which does initialization
 *  of the rules and starts the process of filtering the DNS packets.
 */
int
main(int argc, char **argv)
{
	struct application_dpdk_config dpdk_config;
	char log_buffer[1024] = {};
	struct doca_logger_backend *logger;
	struct doca_program_general_config *doca_general_config;

	dpdk_config.port_config.nb_ports = 2;
	dpdk_config.port_config.nb_queues = 1;
	dpdk_config.port_config.nb_hairpin_q = 4;
	dpdk_config.sft_config = {0};
	dpdk_config.reserve_main_thread = false;

		/* Init and start parsing */
	struct doca_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = true,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("dns_filter_grpc", &type_config, NULL);
	arg_parser_start(argc, argv, &doca_general_config);

	/* Initialize the DPDK settings */
	dpdk_init(&dpdk_config);

	/* Init dns filter */
	dns_filter_init(&dpdk_config);

	/* Allocate a logging backend that will forward the logs to the gRPC client (host) */
	logger = doca_log_create_buffer_backend(log_buffer, sizeof(log_buffer), flush_buffer);
	if (logger == NULL)
		APP_EXIT("Failed to allocate logger");
	doca_log_backend_level_set(logger, DOCA_LOG_LEVEL_DEBUG);

	/* Process packets in another thread so the server could run */
	std::thread dns_filter_thread(
		[](unsigned int nb_queues, unsigned int nb_ports) {
			process_packets(nb_queues, nb_ports);
			server_teardown();
		},
		dpdk_config.port_config.nb_queues, dpdk_config.port_config.nb_ports);

	/* Start the server */
	run_server(doca_general_config->grpc_address);

	/* Closing and releasing resources */
	dns_filter_cleanup(dpdk_config.port_config.nb_ports);

	return 0;
}
