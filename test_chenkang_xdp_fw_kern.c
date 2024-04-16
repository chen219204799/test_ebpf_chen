/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/inet.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 256);
} rxcnt SEC(".maps");

#define XDPBUFSIZE	60
//挂载点-表示在什么情况下触发
SEC("xdp")
int xdp_prog1(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	struct iphdr *iph;
	u16 h_proto;
	u64 nh_off;
	int rc = XDP_PASS;
	u32 ipproto = 0;
	long *value;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	h_proto = eth->h_proto;
	if (h_proto == htons(ETH_P_IP)) {
		//取IPv6地址
		iph = data + nh_off;
		//长度溢出检查
		if (iph + 1 > data_end)
			return XDP_DROP;
		//判断是否阻断IP
		if (0x5801a8c0 == iph->saddr) //192.168.1.88
		{
			ipproto = 99;
			//return XDP_DROP;
		}
	} else if (h_proto == htons(ETH_P_IPV6)) {
		//取IPv6地址
		ip6h = data + nh_off;
		//长度溢出检查
		if (ip6h + 1 > data_end)
			return XDP_DROP;
		if(0xaabbccdd == ip6h->saddr.in6_u.u6_addr32[0] && 
			0xaabbccdd == ip6h->saddr.in6_u.u6_addr32[1] && 
			0xaabbccdd == ip6h->saddr.in6_u.u6_addr32[2] && 
			0xaabbccdd == ip6h->saddr.in6_u.u6_addr32[3])
		{
			return XDP_DROP;
		}
	} else {
		return XDP_PASS;
	}
	
	
	value = bpf_map_lookup_elem(&rxcnt, &ipproto);
	if (value)
		*value += 1;

	return rc;
}

char _license[] SEC("license") = "GPL";
