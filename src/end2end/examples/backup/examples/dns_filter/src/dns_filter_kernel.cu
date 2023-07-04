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

#include "dns_filter_kernel.h"
/* disable gnu_printf  warnings */
#define gnu_printf printf
#include <rte_ethdev.h>

extern "C" void print_l4_header_gpu_wrapper(struct rte_ipv4_hdr * gpu_ipv4_hdr, uint8_t ip_hdr_len);

__global__ void
print_l4_header_gpu(struct rte_ipv4_hdr * gpu_ipv4_hdr, uint8_t ip_hdr_len)
{
        uint8_t *l4_hdr;
        const struct rte_tcp_hdr *tcp_hdr;
        const struct rte_udp_hdr *udp_hdr;
	uint16_t dst_port;
	uint16_t src_port;

        l4_hdr = (typeof(l4_hdr))gpu_ipv4_hdr + ip_hdr_len;

        switch (gpu_ipv4_hdr->next_proto_id) {
        case IPPROTO_UDP:
                udp_hdr = (typeof(udp_hdr))l4_hdr;
                /* conversion from little endian to big endian */
		dst_port = (udp_hdr->dst_port)>>8 | (udp_hdr->dst_port)<<8;
		src_port = (udp_hdr->src_port)>>8 | (udp_hdr->src_port)<<8;

                printf("UDP- DPORT %u, SPORT %u\n", dst_port, src_port);
        break;

        case IPPROTO_TCP:
                tcp_hdr = (typeof(tcp_hdr))l4_hdr;
                /* conversion from little endian to big endian */
 		dst_port = (tcp_hdr->dst_port)>>8 | (tcp_hdr->dst_port)<<8;
                src_port = (tcp_hdr->src_port)>>8 | (tcp_hdr->src_port)<<8;

                printf("TCP- DPORT %u, SPORT %u\n", dst_port, src_port);
        break;

        default:
                printf("Unsupported L4 protocol!\n");
        }
}

void print_l4_header_gpu_wrapper(struct rte_ipv4_hdr * gpu_ipv4_hdr, uint8_t ip_hdr_len){
        printf("CUDA kernel launch for printing a packet received\n");
	print_l4_header_gpu<<<1,1>>>(gpu_ipv4_hdr, ip_hdr_len);
	cudaDeviceSynchronize();
}
