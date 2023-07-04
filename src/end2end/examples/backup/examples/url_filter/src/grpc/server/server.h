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

#ifndef SERVER_H
#define SERVER_H

#include <grpcpp/grpcpp.h>

#include "url_filter.grpc.pb.h"

using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::Status;

class UrlFilterImpl : public URLFilter::Service {
	public:
		Status Subscribe(ServerContext *context, const ::SubscribeReq *request,
			 ServerWriter<::LogRecord> *writer) override;

		Status Create(ServerContext* context, const ::CreateReq *request,
			::CreateResp *response) override;

		Status Add(ServerContext *context, const ::FilterRule *request,
			::AddResp *response) override;

		Status Commit(ServerContext *context, const ::CommitReq *request,
			::CommitResp *response) override;

		Status Quit(ServerContext *context, const ::QuitReq *request,
			::QuitResp *response) override;
};

#endif /* SERVER_H */
