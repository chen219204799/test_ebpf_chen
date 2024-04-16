#include <uapi/linux/bpf.h>  
#include <linux/in.h>  
#include <linux/ip.h> 
#include "trace_helpers.h"
  
SEC("filter")  
int block_ip(struct __sk_buff *skb) {  
    struct ethhdr *eth = bpf_hdr_pointer(skb, ETH_HLEN);  
    if (eth->h_proto != htons(ETH_P_IP))  
        //return TC_ACT_SHOT; // 非 IP 数据包，直接丢弃  
        return TC_ACT_OK;
  
    struct iphdr *ip = bpf_hdr_pointer(skb, sizeof(struct ethhdr));  
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)  
        //return TC_ACT_SHOT; // 非 TCP/UDP 数据包，直接丢弃  
        return TC_ACT_OK;
  
    // 假设我们有一个 BPF map 存储要阻断的 IP 地址  
    // 这里用硬编码的 IP 地址作为示例  
    __u32 block_ip = 0x01020304; // 要阻断的 IP 地址，网络字节序  
    if (ip->saddr == block_ip) {  
        return TC_ACT_SHOT; // 阻断来自这个 IP 地址的数据包  
    }
    char msg[] = "Hello BPF World!";
    bpf_trace_printk(msg, sizeof(msg));
  
    return TC_ACT_OK; // 允许数据包通过  
}  
  
char _license[] SEC("license") = "GPL";
