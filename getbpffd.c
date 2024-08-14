// This program get the file descriptor of a BPF program by its ID.
// Usage: get-bpf-fd <prog_id>
// Example: get-bpf-fd 1
// build with gcc get-bpf-fd.c -o get-bpf-fd -lbpf

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

int get_bpf_prog_fd_by_id(__u32 prog_id) {
    printf("Attempting to get file descriptor for BPF program ID: %u\n", prog_id);
    int fd = bpf_prog_get_fd_by_id(prog_id);
    if (fd < 0) {
        perror("bpf_prog_get_fd_by_id");
        return -1;
    }
    printf("Obtained file descriptor: %d\n", fd);
    return fd;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <prog_id>\n", argv[0]);
        return 1;
    }

    __u32 prog_id = (__u32)atoi(argv[1]);
    printf("Parsed program ID: %u\n", prog_id);
    int fd = get_bpf_prog_fd_by_id(prog_id);
    if (fd >= 0) {
        printf("File descriptor for program ID %u is %d\n", prog_id, fd);
        close(fd);
    }
    return 0;
}