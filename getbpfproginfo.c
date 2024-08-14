
// clang-format off
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <errno.h>
// clang-format on

// Define the bpf syscall wrapper
int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_prog_query(int ifindex, __u32 attach_type) {

  // Create a raw socket
  int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_fd < 0) {
    perror("socket");
    return 1;
  }

  // Bind the socket to the interface
  struct sockaddr_ll sll = {
      .sll_family = AF_PACKET,
      .sll_ifindex = ifindex,
      .sll_protocol = htons(ETH_P_ALL),
  };

  if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind");
    close(sock_fd);
    return 1;
  }

  union bpf_attr attr = {
      .query =
          {
              .target_fd = sock_fd,
              .attach_type = attach_type,
              .query_flags = 0,
              .prog_ids = 0,
              .prog_cnt = 0,
          },
  };

  // First call to get the number of attached programs
  if (bpf(BPF_PROG_QUERY, &attr, sizeof(attr)) != 0) {
    perror("bpf(BPF_PROG_QUERY)");
    return 1;
  }

  __u32 prog_cnt = attr.query.prog_cnt;
  __u32 *prog_ids = malloc(prog_cnt * sizeof(__u32));
  if (!prog_ids) {
    perror("malloc");
    return 1;
  }

  // Second call to get the program IDs
  attr.query.prog_ids = (unsigned long long)prog_ids;
  if (bpf(BPF_PROG_QUERY, &attr, sizeof(attr)) != 0) {
    perror("bpf(BPF_PROG_QUERY)");
    free(prog_ids);
    return 1;
  }

  printf("Number of attached programs: %u\n", prog_cnt);
  for (__u32 i = 0; i < prog_cnt; i++) {
    printf("Program ID %u: %u\n", i, prog_ids[i]);
  }

  free(prog_ids);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <prog_id>\n", argv[0]);
    return 1;
  }

  __u32 prog_id = (__u32)atoi(argv[1]);

  // const char *ifname = argv[2];
  // //   __u32 if_index = (__u32)atoi(argv[2]);

  // int ifindex = if_nametoindex(ifname);
  // if (ifindex == 0) {
  //   perror("if_nametoindex");
  //   return 1;
  // }

  // printf("Parsed program ID: %u, if_name: %s, ifindex: %d\n", prog_id,
  // ifname,
  //        ifindex);

  printf("Parsed program ID: %u\n", prog_id);

  union bpf_attr attr = {
      .prog_id = prog_id,
  };

  int bpf_prog_fd = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
  if (bpf_prog_fd < 0) {
    printf("syscall return value: %d\n", bpf_prog_fd);
    perror("bpf(BPF_PROG_GET_FD_BY_ID)");
    return 1;
  }

  printf("File descriptor for BPF Prog %d: %d\n", prog_id, bpf_prog_fd);

  struct bpf_prog_info info = {};
  __u32 info_len = sizeof(info);

  union bpf_attr info_attr = {
      .info.bpf_fd = bpf_prog_fd,
      .info.info_len = info_len,
      .info.info = (unsigned long long)&info,
  };

  if (bpf(BPF_OBJ_GET_INFO_BY_FD, &info_attr, sizeof(info_attr)) != 0) {
    perror("bpf(BPF_OBJ_GET_INFO_BY_FD)");
    close(bpf_prog_fd);
    return 1;
  }

  printf("Program ID: %u\n", info.id);
  printf("Program Type: %u\n", info.type);
  printf("Program Name: %s\n", info.name);
  printf("Program Loaded At: %llu\n", info.load_time);
  printf("Program Run Count: %llu\n", info.run_cnt);
  printf("Program Run Time: %llu\n", info.run_time_ns);

  // if (bpf_prog_query(ifindex, BPF_CGROUP_INET_INGRESS) != 0) {
  //   close(bpf_prog_fd);
  //   return 1;
  // }

  close(bpf_prog_fd);
  return 0;
}
