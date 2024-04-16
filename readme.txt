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


