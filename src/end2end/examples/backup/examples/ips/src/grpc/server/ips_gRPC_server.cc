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

#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_compat.h>
#include <rte_sft.h>

#include <doca_dpi.h>
#include <doca_log.h>

#include <grpc/log_forwarder.h>
#include <flow_offload.h>
#include <arg_parser.h>

#include "ips_worker.h"
#include "ips_core.h"
#include "server.h"
#include "orchestration.h"

DOCA_LOG_REGISTER(IPS::GRPC);

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ClientContext;
using grpc::Status;
using grpc::Channel;

static struct ips_config ips_config = {{0}};

std::condition_variable server_lock;

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
IPSImpl::Subscribe(ServerContext *context, const ::SubscribeReq *request,
		  ServerWriter<::LogRecord> *writer)
{
	(void)context;
	(void)request;

	if (!subscribe_client(&subscribed_clients, writer))
		return Status::CANCELLED;
	return Status::OK;
}

Status
IPSImpl::Quit(ServerContext *context, const ::QuitReq *request, ::QuitResp *response)
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
run_server(const char *arg)
{
	std::mutex mutex;
	std::unique_lock<std::mutex> lock(mutex);

	/* Check if we got a port or if we are using the default one */
	std::string server_address(arg);
	if (server_address.find(':') == std::string::npos)
		server_address += ":" + std::to_string(eNetworkPort::k_Ips);

	/* Make sure the stream won't close on us and shorten delays */
	grpc::EnableDefaultHealthCheckService(true);

	/* Config the gRPC server */
	ServerBuilder builder;
	builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());

	/* Add the services */
	IPSImpl app_service;
	DocaOrchestrationImpl orchestration_service;
	builder.RegisterService(&app_service);
	builder.RegisterService(&orchestration_service);

	/* Start the logger thread */
	std::thread logger_thread([]{forward_log_records(&log_records_queue, &subscribed_clients);});

	std::unique_ptr<Server> server(builder.BuildAndStart());
	DOCA_LOG_INFO("gRPC server started");

	/* The main thread loop to collect statistics and receive requests */
	while (!force_quit) {
		if (server_lock.wait_for(lock, std::chrono::milliseconds(100)) == std::cv_status::no_timeout)
			break;
		if (ips_config.create_csv) {
			sleep(1);
			if (sig_database_write_to_csv(ips_config.csv_filename) != 0)
				APP_EXIT("CSV file access failed");
		}
		if (ips_config.collect_netflow_stat && send_netflow() != 0)
			APP_EXIT("Unexpected Netflow failure");
	}

	/* Officially shut down the server */
	server->Shutdown();
	logger_thread.join();
}

int
main(int argc, char *argv[])
{
        char log_buffer[1024] = {};
        struct doca_logger_backend *logger;
	struct ips_worker_attr ips_worker_attr = {0};
	struct application_dpdk_config dpdk_config;

	dpdk_config.port_config.nb_ports = 2;
	dpdk_config.port_config.nb_queues = 2;
	dpdk_config.port_config.nb_hairpin_q = 4;
	dpdk_config.sft_config = {1, 1, 0, 1};
	dpdk_config.reserve_main_thread = true;

	/* init and start parsing */
	struct doca_program_general_config *doca_program_general_config;
	struct doca_program_type_config type_config = {
		.is_dpdk = true,
		.is_grpc = true,
	};

	/* Parse cmdline/json arguments */
	arg_parser_init("ips", &type_config, &ips_config);
	register_ips_params();
	arg_parser_start(argc, argv, &doca_program_general_config);

	/** init DPDK cores and sft */
	dpdk_init(&dpdk_config);

        /* Allocate a logging backend that will forward the logs to the gRPC client (host) */
	logger = doca_log_create_buffer_backend(log_buffer, sizeof(log_buffer), flush_buffer);
	if (logger == NULL)
		APP_EXIT("Failed to allocate logger");

	/* IPS init **/
	ips_init(&dpdk_config, &ips_config, &ips_worker_attr);

	/* Start the DPI processing */
	ips_worker_lcores_run(dpdk_config.port_config.nb_queues, CLIENT_ID, ips_worker_attr);

	/* Start the server */
	run_server(doca_program_general_config->grpc_address);

	/* End of application flow */
	ips_cleanup(&ips_config);

	return 0;
}
