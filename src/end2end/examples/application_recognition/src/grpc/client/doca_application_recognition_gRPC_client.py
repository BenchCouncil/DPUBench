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
import queue


import common_pb2 as gen_common
import application_recognition_pb2 as gen_pbuf
import application_recognition_pb2_grpc as gen_grpc

APP_NAME = 'Application-Recognition'
FULL_APP_NAME = APP_NAME + ' gRPC Client'

gRPC_PORT = gen_common.eNetworkPort.k_ApplicationRecognition

logger = logging.getLogger(FULL_APP_NAME)
ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(ch)
logger.setLevel(logging.INFO)

def block_stub(stub, sig_id):
	"""Command - block signature.

	Args:
		stub (grpc): grpc client
	"""
	logger.debug('CLI Command - Block')
	try:
		response = stub.Block(gen_pbuf.SigID(id=int(sig_id)))
	except grpc.RpcError as e:
		print(e.details())


def unblock_stub(stub, sig_id):
	"""Command - unblock signature.

	Args:
		stub (grpc): grpc client
	"""
	logger.debug('CLI Command - Unblock')
	try:
		response = stub.Unblock(gen_pbuf.SigID(id=int(sig_id)))
	except grpc.RpcError as e:
		print(e.details())

def quit_stub(stub):
	"""Command - exit the application and get the packet statistics.

	Args:
		stub (grpc): grpc client
	"""
	logger.debug('CLI Command - Quit')
	stub.Quit(gen_pbuf.QuitReq())

cli_command_tree = {
                    'block':   (('[sig_id]',), 'Block SIG ID', block_stub),
                    'unblock': (('[sig_id]',), 'Unblock SIG ID', unblock_stub),
                    'quit':    ((), 'Exit application', quit_stub),
		   }


def cli_usage():
	"""Print the usage instructions for the cli."""
	print(f'{APP_NAME} CLI Commands:')
	for cmd, (args, desc, _) in cli_command_tree.items():
		print(f'\t{" ".join([cmd] + list(args))} ')
		print(f'\t\t{desc}')

def cli_loop(stub):
	"""Loop and receive user-commands through the cli.

	Args:
		stub (grpc): grpc client
	"""
	logger.debug('Starting the CLI loop')

	handler = None
	user_command = ''
	while handler != quit_stub:
		user_command = input(APP_NAME + " >> ").strip()
		args = shlex.split(user_command)
		if len(args) == 0:
			continue
		command_name = args[0].lower()

		# The help command
		if command_name == 'help':
			if len(args) != 1:
				print('Invalid command arguments')
				# fallthrough
			cli_usage()
			continue

		# Unknown command
		if command_name not in cli_command_tree:
			print('Command not found')
			cli_usage()
			continue

		cmd_args, _, handler = cli_command_tree[command_name]
		# Not enough CLI arguments
		if len(cmd_args) != len(args) - 1:
			print('Invalid command arguments')
			cli_usage()
			continue
		args_content = {}
		parsed_correctly = True
		for idx in range(len(cmd_args)):
			# Template argument
			if cmd_args[idx].startswith('['):
				args_content[cmd_args[idx][1:-1]] = args[idx + 1]
				continue
			# Fixed argument
			if cmd_args[idx] != args[idx + 1].lower():
				parsed_correctly = False
				break

		if not parsed_correctly:
			print('Invalid command arguments')
			cli_usage()
			continue

		# Invoke the command
		handler(stub, **args_content)

	logger.debug("Quit the CLI loop")


def print_log_records(notification_stream):
	# get push notification and print them
	for log_record in notification_stream:
		print(log_record.log_line, end='')


@click.group(help='DOCA Application-Recognition gRPC Client', invoke_without_command=True)
@click.argument('server_address')
@click.option('-d', '--debug', is_flag=True, default=False)
def cli(server_address, debug):
	# gRPC-generic commands and options
	if debug:
		logger.setLevel(logging.DEBUG)

	if ':' not in server_address:
		server_address = f'{server_address}:{gRPC_PORT}'

	logger.info(f'Connecting to the {APP_NAME} gRPC server on the DPU: {server_address}')
	channel = grpc.insecure_channel(server_address)

	try:
		stub = gen_grpc.ARStub(channel)
		notification_stream = stub.Subscribe(gen_pbuf.SubscribeReq())
		# Invoke a thread responsible for the log records
		report_thread = threading.Thread(target=print_log_records, args=(notification_stream,), daemon=True)
		report_thread.start()
		# Interactive CLI Session
		cli_loop(stub)
	except RuntimeError as e:
		logger.error('Failed to connect to the gRPC server on the DPU')

	report_thread.join()
	logger.info('Finished Successfully')


if __name__ == '__main__':
	cli()
