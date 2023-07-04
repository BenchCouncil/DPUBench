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

#ifndef ORCHESTRATION_H
#define ORCHESTRATION_H

#include <grpcpp/grpcpp.h>

#include "common.grpc.pb.h"

using grpc::ServerContext;
using grpc::Status;

class DocaOrchestrationImpl : public DocaOrchestration::Service {
	public:
		Status HealthCheck(ServerContext *context, const ::HealthCheckReq *request,
			::HealthCheckResp *response) override;

		Status Destroy(ServerContext *context, const ::DestroyReq *request,
			::DestroyResp *response) override;
};

#endif /* ORCHESTRATION_H */
