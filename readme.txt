此demo为eBPF机制下的源IP防火墙

#环境如下：
VMware Workstation
	Ubantu-22.04.4-64
	kernel version: 6.5.0-27-generic
	gcc version 11.4.0
	Ubuntu clang version 14.0.0-1ubuntu1.1
	
#代码基于内核源码中的samples/bpf修改
#使用时将代码拷贝至/usr/src/linux-source-6.5.0/samples/bpf
cp ./* /usr/src/linux-source-6.5.0/samples/bpf
cd /usr/src/linux-source-6.5.0/
#使用如下命令编译即可
make M=samples/bpf

#执行命令如下
./test_chenkang_xdp_fw -S intface_name

后续代码优化思路
1.可以将工程从/usr/src/linux-source-6.5.0/samples/bpf内核路径中摘出。
2.可以以文件方式或程序启动参数方式载入需要阻断的IP地址。
3.可以优化阻断的条件，可以是五元组的任意条件。
4.可以通过用户态程序实时更新map，做到动态阻断。
