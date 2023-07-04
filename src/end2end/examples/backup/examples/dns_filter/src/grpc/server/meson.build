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

app_grpc_static_srcs = [
	APP_NAME + '_gRPC_server.cc',
]

cpp_args = [
	'-std=c++11'
]

dependency_protobuf = dependency('protobuf', required : false)
if not dependency_protobuf.found()
	error('Please set PKG_CONFIG_PATH to gRPC packages path, for further instructions please refer to the DOCA DPU Runtime guide for gRPC')
endif
grpc_dependencies = [dependency_protobuf]
grpc_dependencies += dependency('grpc++', required : true)

protoc = find_program('protoc', required : true)
grpc_cpp_plugin = find_program('grpc_cpp_plugin', required : true)

app_base = '../..'
common_base = app_base + '/../../common/src'

inc_dirs  = app_inc_dirs
inc_dirs += include_directories(app_base)

adjusted_app_srcs = []
foreach src_file : app_srcs
	adjusted_app_srcs += [app_base + '/' + src_file]
endforeach

adjusted_app_srcs += [
	common_base + '/grpc/log_forwarder.cc'
]

common_gen = generator(protoc, \
			output    : ['@BASENAME@.pb.cc', '@BASENAME@.pb.h'],
			arguments : ['--proto_path=@CURRENT_SOURCE_DIR@/' + common_base + '/grpc',
			             '--cpp_out=@BUILD_DIR@',
			             '@INPUT@'])

orchestration_gen = generator(protoc, \
			output    : ['@BASENAME@.grpc.pb.cc', '@BASENAME@.grpc.pb.h'],
			arguments : ['--proto_path=@CURRENT_SOURCE_DIR@/' + common_base + '/grpc',
			             '--grpc_out=@BUILD_DIR@',
			             '--plugin=protoc-gen-grpc=' + grpc_cpp_plugin.path(),
			             '@INPUT@'])

proto_gen = generator(protoc, \
			output    : ['@BASENAME@.pb.cc', '@BASENAME@.pb.h'],
			arguments : ['--proto_path=@CURRENT_SOURCE_DIR@/..',
			             '--proto_path=@CURRENT_SOURCE_DIR@/' + common_base + '/grpc',
			             '--cpp_out=@BUILD_DIR@',
			             '@INPUT@'])

grpc_gen = generator(protoc, \
			output    : ['@BASENAME@.grpc.pb.cc', '@BASENAME@.grpc.pb.h'],
			arguments : ['--proto_path=@CURRENT_SOURCE_DIR@/..',
			             '--proto_path=@CURRENT_SOURCE_DIR@/' + common_base + '/grpc',
			             '--grpc_out=@BUILD_DIR@',
			             '--plugin=protoc-gen-grpc=' + grpc_cpp_plugin.path(),
			             '@INPUT@'])

common_proto = common_base + '/grpc/common.proto'
gen_common = common_gen.process(common_proto)
gen_orchestration = orchestration_gen.process(common_proto)

app_proto = '../' + APP_NAME + '.proto'
gen_proto = proto_gen.process(app_proto)
gen_grpc  = grpc_gen.process(app_proto)

executable('doca_' + APP_NAME + '_grpc', adjusted_app_srcs + app_grpc_static_srcs,
		gen_proto, gen_grpc, gen_common, gen_orchestration,
		cpp_args : cpp_args,
		dependencies : app_dependencies + grpc_dependencies,
		include_directories : inc_dirs,
		install: false)
