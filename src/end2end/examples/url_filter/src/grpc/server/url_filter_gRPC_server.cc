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

#include <signal.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/wait.h>
#include <condition_variable>
#include <string>

#include <rte_compat.h>
#include <rte_sft.h>

#include <doca_dpi.h>
#include <doca_log.h>

#include <grpc/log_forwarder.h>
#include <utils.h>

#include "url_filter_core.h"
#include "orchestration.h"
#include "server.h"

DOCA_LOG_REGISTER(UFLTR::GRPC);

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::ClientContext;
using grpc::Status;
using grpc::Channel;

static struct url_config url_config = {0};

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
	/* Signal the sleeping thread to wake-up */
	server_lock.notify_one();
}

Status
UrlFilterImpl::Subscribe(ServerContext *context, const ::SubscribeReq *request,
			 ServerWriter<::LogRecord> *writer)
{
	(void)context;
	(void)request;

	if (!subscribe_client(&subscribed_clients, writer))
		return Status::CANCELLED;

	return Status::OK;
}

Status
UrlFilterImpl::Create(ServerContext* context, const ::CreateReq *request,
		      ::CreateResp *response)
{
	(void)context;
	(void)request;
	(void)response;

	create_database(DEFAULT_TXT_INPUT);
	return Status::OK;
}

Status
UrlFilterImpl::Add(ServerContext *context, const ::FilterRule *request,
		   ::AddResp *response)
{
	(void)context;
	(void)response;

	create_url_signature(DEFAULT_TXT_INPUT, request->msg().c_str(), request->pcre().c_str());
	return Status::OK;
}

Status
UrlFilterImpl::Commit(ServerContext *context, const ::CommitReq *request,
		      ::CommitResp *response)
{
	(void)context;
	(void)request;
	(void)response;

	compile_and_load_signatures(DEFAULT_TXT_INPUT, DEFAULT_CDO_OUTPUT);
	return Status::OK;
}

Status
UrlFilterImpl::Quit(ServerContext *context, const ::QuitReq *request,
		    ::QuitResp *response)
{
	(void)context;
	(void)request;
	(void)response;

	server_teardown();
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
run_server(const char *raw_server_address)
{
	/* Check if we got a port or if we are using the default one */
	std::string server_address(raw_server_address);
	if (server_address.find(':') == std::string::npos)
		server_address += ":" + std::to_string(eNetworkPort::k_UrlFilter);

	/* Make sure the stream won't close on us and shorten delays */
	grpc::EnableDefaultHealthCheckService(true);

	/* Config the gRPC server */
	ServerBuilder builder;
	builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

	/* Add the services */
	UrlFilterImpl app_service;
	DocaOrchestrationImpl orchestration_service;
	builder.RegisterService(&app_service);
	builder.RegisterService(&orchestration_service);

	/* Start the logger thread */
	std::thread logger_thread([]{forward_log_records(&log_records_queue, &subscribed_clients);});

	std::unique_ptr<Server> server(builder.BuildAndStart());
	DOCA_LOG_INFO("gRPC server started");

	/* Wait for the Quit / Destroy command */
	std::mutex mutex;
	std::unique_lock<std::mutex> lock(mutex);
	server_lock.wait(lock);

	/* Officially shut down the server */
	server->Shutdown();
	logger_thread.join();
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct application_dpdk_config dpdk_config;
	char log_buffer[1024] = {};
	struct doca_logger_backend *logger;
	struct dpi_worker_attr dpi_worker = {0};
	struct doca_program_general_config *doca_general_config;

	/* Init the DPDK configuration struct */
	dpdk_config.port_config.nb_ports = 2;
	dpdk_config.port_config.nb_queues = 2;
	dpdk_config.port_config.nb_hairpin_q = 4;
	dpdk_config.sft_config = {1, 1, 1, 1};
	dpdk_config.reserve_main_thread = true;

	/* Init and start parsing */
	struct doca_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = true,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("url_filter_grpc", &type_config, &url_config);
	register_url_params();
	arg_parser_start(argc, argv, &doca_general_config);

	/* Initialize the DPDK settings */
	dpdk_init(&dpdk_config);

	/* Allocate a logging backend that will forward the logs to the gRPC client (host) */
	logger = doca_log_create_buffer_backend(log_buffer, sizeof(log_buffer), flush_buffer);
	if (logger == NULL)
		APP_EXIT("Failed to allocate logger");
	doca_log_backend_level_set(logger, DOCA_LOG_LEVEL_DEBUG);

	/* All needed preparations - Check for required files, init the DPI, etc. */
	url_filter_init(&dpdk_config, &url_config, &dpi_worker);

	/* Start the DPI processing */
	dpi_worker_lcores_run(dpdk_config.port_config.nb_queues, CLIENT_ID, dpi_worker);

	/* Start the server */
	run_server(doca_general_config->grpc_address);

	/* Remove used files and free resources */
	url_filter_cleanup();

	return 0;
}
