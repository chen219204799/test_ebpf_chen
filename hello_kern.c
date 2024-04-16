#include <bpf/bpf_helpers.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("tracepoint/syscalls/sys_enter_execve")		//触发的事件类型/系统调用
int bpf_prog(void *ctx)							//触发事件时调用的函数
{
	char msg[] = "Hello BPF World!";
	bpf_trace_printk(msg, sizeof(msg));			//将信息写入管道，等待用户态读取
	
	return 0;
}

char _license[] SEC("license") = "GPL";
