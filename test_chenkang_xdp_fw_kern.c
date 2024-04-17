#define KBUILD_MODNAME "test_chenkang_xdp_fw"
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
#include <linux/fcntl.h>
#include <linux/unistd.h>
#include <linux/bpf.h>

#define type_drop 99

struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};

struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv4_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} ipv4_lpm_map SEC(".maps");


struct ipv6_lpm_key {
        __u32 prefixlen;
        __u32 data[4];
};

struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct ipv6_lpm_key);
        __type(value, __u32);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 255);
} ipv6_lpm_map SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 256);
} rxcnt SEC(".maps");

/*查找ip地址是否存在map中 存在return地址 否则返回NULL*/
void *lookup_by_addr(__u32 ipaddr);
void *lookup_by_addr(__u32 ipaddr)
{
        struct ipv4_lpm_key key = {
                .prefixlen = 32,
                .data = ipaddr
        };

        return bpf_map_lookup_elem(&ipv4_lpm_map, &key);
}

/*查找ipv6地址是否存在map中 存在return地址 否则返回NULL*/
void *lookup_by_addrv6(__u32 ipaddr[4]);
void *lookup_by_addrv6(__u32 ipaddr[4])
{
        struct ipv6_lpm_key key = {
			key.prefixlen = 128,
			key.data[0] = ipaddr[0],
			key.data[1] = ipaddr[1],
			key.data[2] = ipaddr[2],
			key.data[3] = ipaddr[3]
		};
        return bpf_map_lookup_elem(&ipv6_lpm_map, &key);
}




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
	int rc = XDP_PASS;//默认动作放行
	u32 type = 0;
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
		if (lookup_by_addr(iph->saddr)) //192.168.1.88  0x5801a8c0
		{
			type = type_drop;
			rc = XDP_DROP;
		}
	} else if (h_proto == htons(ETH_P_IPV6)) {
		//取IPv6地址
		ip6h = data + nh_off;
		//长度溢出检查
		if (ip6h + 1 > data_end)
			return XDP_DROP;
		//IP地址阻断
		if(lookup_by_addrv6(ip6h->saddr.in6_u.u6_addr32))
		{
			type = type_drop;
			rc = XDP_DROP;
		}
	} else {
		return rc;
	}
	
	//设置丢包计数
	value = bpf_map_lookup_elem(&rxcnt, &type);
	if (value)
		*value += 1;

	return rc;
}

char _license[] SEC("license") = "GPL";
