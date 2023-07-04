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

#include "application_recognition.grpc.pb.h"

using grpc::ServerContext;
using grpc::ServerWriter;
using grpc::Status;

class ARImpl : public AR::Service {
	public:
		Status Subscribe(ServerContext *context, const ::SubscribeReq *request,
			ServerWriter<::LogRecord> *writer) override;

		Status Block(ServerContext *context, const ::SigID *request,
			::BlockResp *response) override;

		Status Unblock(ServerContext *context, const ::SigID *request,
			::UnblockResp *response) override;

		Status Quit(ServerContext *context, const ::QuitReq *request,
			::QuitResp *QuitResponse) override;
};

#endif /* SERVER_H */
