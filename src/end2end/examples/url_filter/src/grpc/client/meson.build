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

client_src = 'doca_' + APP_NAME + '_gRPC_client.py'

protoc = find_program('protoc', required : true)
grpc_py_plugin = find_program('grpc_python_plugin', required : true)

app_base = '../..'
common_base = app_base + '/../../common/src'

common_gen = generator(protoc, \
			output    : ['@BASENAME@_pb2.py'],
			arguments : ['--proto_path=@CURRENT_SOURCE_DIR@/' + common_base + '/grpc',
			             '--python_out=@BUILD_DIR@',
			             '@INPUT@'])

proto_gen = generator(protoc, \
			output    : ['@BASENAME@_pb2.py'],
			arguments : ['--proto_path=@CURRENT_SOURCE_DIR@/..',
			             '--proto_path=@CURRENT_SOURCE_DIR@/' + common_base + '/grpc',
			             '--python_out=@BUILD_DIR@',
			             '@INPUT@'])

grpc_gen = generator(protoc, \
			output    : ['@BASENAME@_pb2_grpc.py'],
			arguments : ['--proto_path=@CURRENT_SOURCE_DIR@/..',
			             '--proto_path=@CURRENT_SOURCE_DIR@/' + common_base + '/grpc',
			             '--grpc_out=@BUILD_DIR@',
			             '--plugin=protoc-gen-grpc=' + grpc_py_plugin.path(),
			             '@INPUT@'])

common_proto = common_base + '/grpc/common.proto'
gen_common = common_gen.process(common_proto)

app_proto = '../' + APP_NAME + '.proto'
gen_proto = proto_gen.process(app_proto)
gen_grpc  = grpc_gen.process(app_proto)

# Hack to force the generation of non-executable generated files
foreach gen : [['gRPC_client', client_src], ['py_common', gen_common], ['py_proto', gen_proto], ['py_grpc', gen_grpc]]
	py_proc = custom_target(gen[0],
				command: [ find_program('cp', 'copy'), '@INPUT@', '@OUTPUT@' ],
				input : gen[1],
				output : '@BASENAME@.py',
				install : false,
				build_by_default : true)
endforeach
