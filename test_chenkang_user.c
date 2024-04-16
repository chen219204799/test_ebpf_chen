#include <bpf/bpf.h>  
#include <bpf/libbpf.h>  
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>  
#include "trace_helpers.h"
  
int main(int argc, char **argv) {  
    struct bpf_program *prog;  
    int prog_fd;
    char filename[256];
  
    // 初始化 libbpf  
    if (bpf_init() < 0) {  
        perror("Can't init libbpf");  
        return 1;  
    }  
    snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
    // 加载 BPF 对象文件  
    //struct bpf_object *obj = bpf_object__open_file(filename, BPF_OBJECT_FLAG_LOAD_PROGRAMS);  
    struct bpf_object *obj = bpf_object__open_file(filename, NULL);  
    if (!obj) {  
        fprintf(stderr, "Error loading BPF object file\n");  
        return 1;  
    }  
  
    // 获取第一个（也是唯一的）程序  
    prog = bpf_object__find_program_by_title(obj, "filter");  
    if (!prog) {  
        fprintf(stderr, "Error finding BPF program\n");  
        return 1;  
    }  
  
    // 加载程序到内核  
    prog_fd = bpf_program__load(prog);  
    if (prog_fd < 0) {  
        perror("Error loading BPF program");  
        return 1;  
    }  
  
    printf("BPF program loaded with file descriptor %d\n", prog_fd);  
    read_trace_pipe();

    // TODO: 将程序附加到网络设备的 hook 点  
    // 这通常涉及使用 tc (traffic control) 命令或相应的系统调用  
  
    // 清理  
    bpf_object__close(obj);  
    close(prog_fd);  
    return 0;  
}
