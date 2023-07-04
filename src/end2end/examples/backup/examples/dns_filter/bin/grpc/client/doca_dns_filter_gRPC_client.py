#!/usr/bin/python3

#
# Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

import sys
import click
import logging
import shlex
import concurrent.futures as futures
import threading
import grpc

import common_pb2 as gen_common
import dns_filter_pb2 as gen_pbuf
import dns_filter_pb2_grpc as gen_grpc

APP_NAME = 'DNS-Filter'
FULL_APP_NAME = APP_NAME + ' gRPC Client'

gRPC_PORT = gen_common.eNetworkPort.k_DnsFilter

logger = logging.getLogger(FULL_APP_NAME)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(ch)
logger.setLevel(logging.INFO)


@click.group(help='DOCA DNS-Filter gRPC Client', invoke_without_command=True)
@click.argument('server_address')
@click.option('-d', '--debug', is_flag=True, default=False)
def cli(server_address, debug):
	global dns_filter_stub
	# gRPC-generic commands and options
	if debug:
		logger.setLevel(logging.DEBUG)

	if ':' not in server_address:
		server_address = f'{server_address}:{gRPC_PORT}'

	logger.info(
		f'Connecting to the {APP_NAME} gRPC server on the DPU: {server_address}')
	channel_options = [
		('grpc.keepalive_time_ms', 500),
		('grpc.keepalive_timeout_ms', 200)
	]
	channel = grpc.insecure_channel(server_address, options=channel_options)

	try:
		dns_filter_stub = gen_grpc.DNSFilterStub(channel)
		notification_stream = dns_filter_stub.Subscribe(gen_pbuf.SubscribeReq())
	except RuntimeError:
		logger.error('Failed to connect to the gRPC server on the DPU')

	# get push notification and print them
	for log_record in notification_stream:
		print(log_record.log_line, end='')

	# Teardown
	logger.info('Finished Successfully')


if __name__ == '__main__':
	cli()
