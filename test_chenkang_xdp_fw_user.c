// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 PLUMgrid
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

static int ifindex;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static __u32 prog_id;
#define type_drop 99

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};
struct ipv6_lpm_key {
        __u32 prefixlen;
        __u32 data[4];
};



//添加IP地址进地址map
int add_prefix_entry(int lpm_fd, __u32 addr, __u32 prefixlen, void *value);
int add_prefix_entry(int lpm_fd, __u32 addr, __u32 prefixlen, void *value)
{
        struct ipv4_lpm_key ipv4_key = {
                .prefixlen = prefixlen,
                .data = addr
        };
        return bpf_map_update_elem(lpm_fd, &ipv4_key, value, BPF_ANY);
}


int add_prefix_entry_v6(int lpm_fd, __u32 addr[4], __u32 prefixlen, void *value);
int add_prefix_entry_v6(int lpm_fd, __u32 addr[4], __u32 prefixlen, void *value)
{
        struct ipv6_lpm_key ipv6_key = {
                .prefixlen = prefixlen,
				.data[0] = addr[0],
				.data[1] = addr[1],
				.data[2] = addr[2],
				.data[3] = addr[3]
        };
        return bpf_map_update_elem(lpm_fd, &ipv6_key, value, BPF_ANY);
}



static void int_exit(int sig)
{
	__u32 curr_prog_id = 0;

	if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id)) {
		printf("bpf_xdp_query_id failed\n");
		exit(1);
	}
	if (prog_id == curr_prog_id)
		bpf_xdp_detach(ifindex, xdp_flags, NULL);
	else if (!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("program on interface changed, not removing\n");
	exit(0);
}

/* simple per-protocol drop counter
 */
static void poll_stats(int map_fd, int interval)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	__u64 values[nr_cpus], prev[UINT8_MAX] = { 0 };
	int i;

	while (1) {
		__u32 key = UINT32_MAX;

		sleep(interval);

		while (bpf_map_get_next_key(map_fd, &key, &key) == 0) {
			__u64 sum = 0;

			assert(bpf_map_lookup_elem(map_fd, &key, values) == 0);
			for (i = 0; i < nr_cpus; i++)
				sum += values[i];
			
			if (sum > prev[key] && type_drop == key)
				printf("drop rate: %10llu pkt/s     drop num:%10llu pkts\n",(sum - prev[key]) / interval,sum);
			
			prev[key] = sum;
		}
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] IFACE\n\n"
		"OPTS:\n"
		"    -S    use skb-mode\n"
		,prog);
}

int main(int argc, char **argv)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	const char *optstr = "FSN";
	int prog_fd, map_info_fd, map_iplist_fd,map_ipv6list_fd,opt;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map_info = NULL;
	struct bpf_map *map_iplist = NULL;
	long *value;
	char filename[256];
	int err;
	__u32 ipv4_addr = 0x5801a8c0;
	__u32 prefixlen_v4 = 32;

	__u32 ipv6_addr[4] = {0xaabbccdd,0xaabbccdd,0xaabbccdd,0xaabbccdd};
	__u32 prefixlen_v6 = 128;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	//获取网口索引
	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	//根据对应的内核程序文件生成obj对象
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj))
		return 1;

	//根据获取的obj拿到内核函数并设置类型
	prog = bpf_object__next_program(obj, NULL);
	bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

	//加载到内核空间
	err = bpf_object__load(obj);
	if (err)
		return 1;

	//获取内核空间的obj   ->prog->fd索引
	prog_fd = bpf_program__fd(prog);

	

	//获取obj的map_rxcnt信息
	map_info = bpf_object__find_map_by_name(obj,"rxcnt");
	if (!map_info) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	//printf("----------------map_info:%p--------------\n",map_info);

	//获取map_rxcnt的fd
	map_info_fd = bpf_object__find_map_fd_by_name(obj,"rxcnt");
	if (!map_info_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		return 1;
	}
	//printf("----------------map_info_fd:%d--------------\n",map_info_fd);


	
	//获取obj的ipv4_lpm_map信息
	map_iplist = bpf_object__find_map_by_name(obj, "ipv4_lpm_map");
	if (!map_iplist) {
		printf("finding a map in obj file failed\n");
		return 1;
	}
	//获取ipv4_lpm_map的fd
	map_iplist_fd = bpf_object__find_map_fd_by_name(obj, "ipv4_lpm_map");
	if (!map_iplist_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		return 1;
	}
	//添加IPv4地址进ipv4_lpm_map
	if(add_prefix_entry(map_iplist_fd, ipv4_addr, prefixlen_v4,&value)){
		printf("set ip_addr failed \n");
		return 1;
	}


	//获取ipv6_lpm_map的fd
	map_ipv6list_fd = bpf_object__find_map_fd_by_name(obj, "ipv6_lpm_map");
	if (!map_ipv6list_fd) {
		printf("bpf_prog_load_xattr: %s\n", strerror(errno));
		return 1;
	}
	//添加IPv6地址进ipv6_lpm_map
	if(add_prefix_entry_v6(map_ipv6list_fd, ipv6_addr, prefixlen_v6,&value)){
		printf("set ipv6_addr failed \n");
		return 1;
	}
	
	
	//设置信号处理函数 保证用户态进程退出时程序正确处理
	signal(SIGINT, int_exit);//ctrl + c
	signal(SIGTERM, int_exit);//kill 

	//绑定网口上的XDP程序
	if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

	//根据prog_fd获取内核传递的信息
	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		printf("can't get prog info - %s\n", strerror(errno));
		return err;
	}
	prog_id = info.id;

	//循环处理map中的信息,显示到用户态
	poll_stats(map_info_fd, 1);

	return 0;
}
