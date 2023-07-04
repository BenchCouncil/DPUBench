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

project('DOCA_TELEMETRY_CLIENT', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
	files('VERSION')).stdout().strip(),
	license: 'BSD',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.47.1'
)

APP_NAME = 'telemetry_client'

cpp_args = [
	'-std=c++11'
]

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: 'c')

dependency_libdpdk = dependency('libdpdk', required : false)
if not dependency_libdpdk.found()
	error('Please set PKG_CONFIG_PATH to DPDK packages path, for further instructions please refer to the DOCA Reference Applications guide')
endif
app_dependencies = [dependency_libdpdk]
app_dependencies += dependency('doca-utils', required : true)
app_dependencies += dependency('json-c', required : true)

common_dir_path = '../../common/src'
app_inc_dirs = [include_directories(common_dir_path)]

telemetry_app_srcs = [
	'telemetry_client.c',
	'telemetry_config.c',
	common_dir_path + '/arg_parser.c',
]

telemetry_netflow_app_srcs = [
	'telemetry_netflow_config.c'
]

executable('doca_' + APP_NAME, telemetry_app_srcs + telemetry_netflow_app_srcs,
	cpp_args : cpp_args,
	dependencies : app_dependencies,
	include_directories: app_inc_dirs,
	install: false)
