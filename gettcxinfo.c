// clang-format off
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
// clang-format on

int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_prog_query_tc(const char *ifname, enum bpf_attach_type attach_type,
                      __u32 *prog_ids, __u32 prog_cnt, __u32 *prog_cnt_out,
                      unsigned long long *revision_out) {

  int ifindex = if_nametoindex(ifname);
  if (ifindex == 0) {
    perror("if_nametoindex");
    return 1;
  }

  union bpf_attr attr = {.query = {
                             .target_ifindex = ifindex,
                             .attach_type = attach_type,
                             .prog_ids = (uint64_t)prog_ids,
                             .prog_cnt = prog_cnt,
                         }};

  int ret = bpf(BPF_PROG_QUERY, &attr, sizeof(attr));
  if (ret == -1) {
    perror("bpf_prog_query failed");
    return -errno;
  }

  *prog_cnt_out = attr.query.prog_cnt; // Return the number of programs attached
  *revision_out = attr.query.revision; // Return the revision of the BPF program
  return 0;
}

int get_prog_info(__u32 prog_id, struct bpf_prog_info *info, __u32 info_len) {
  union bpf_attr attr = {
      .prog_id = prog_id,
  };

  int bpf_prog_fd = bpf(BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
  if (bpf_prog_fd < 0) {
    printf("syscall return value: %d\n", bpf_prog_fd);
    perror("bpf(BPF_PROG_GET_FD_BY_ID)");
    return 1;
  }

  union bpf_attr info_attr = {
      .info.bpf_fd = bpf_prog_fd,
      .info.info_len = info_len,
      .info.info = (unsigned long long)info,
  };

  if (bpf(BPF_OBJ_GET_INFO_BY_FD, &info_attr, sizeof(info_attr)) != 0) {
    perror("bpf(BPF_OBJ_GET_INFO_BY_FD)");
    close(bpf_prog_fd);
    return 1;
  }

  close(bpf_prog_fd);
  return 0;
}

#define NUM_PROGS 50

int main(int argc, char *argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <ifname> <direction>\n", argv[0]);
    return 1;
  }

  const char *ifname = argv[1];
  const char *direction = argv[2];

  __u32 prog_ids[NUM_PROGS];
  __u32 prog_cnt_out;
  struct bpf_prog_info info_out;
  __u32 info_len = sizeof(info_out);
  unsigned long long revision_out;

  enum bpf_attach_type attach_type;
  if (strcmp(direction, "ingress") == 0) {
    attach_type = BPF_TCX_INGRESS;
  } else if (strcmp(direction, "egress") == 0) {
    attach_type = BPF_TCX_EGRESS;
  } else {
    printf("Invalid direction: %s\n", direction);
    return 1;
  }

  int ret = bpf_prog_query_tc(ifname, attach_type, prog_ids, NUM_PROGS,
                              &prog_cnt_out, &revision_out);
  if (ret == 0) {
    printf("Interface: %s, Direction: %s, Revision: %llu\n", ifname, direction,
           revision_out);
    printf("%-8s  %6s  %-16s\n", "Position", "ID", "Name");
    printf("%-8s  %6s  %-16s\n", "--------", "------", "----------------");
    for (__u32 i = 0; i < prog_cnt_out; i++) {
      info_out = (struct bpf_prog_info){};
      int info_ret = get_prog_info(prog_ids[i], &info_out, info_len);
      if (info_ret == 0) {
        printf("%8u  %6u  %-16s\n", i, prog_ids[i], info_out.name);
      } else {
        printf("%8u  %6u  %-16s\n", i, prog_ids[i], "Failed to get name");
      }
    }
  }

  return ret;
}
