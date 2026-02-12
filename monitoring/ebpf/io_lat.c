// io_lat.c
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/major.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <math.h>

#include "io_lat.skel.h"

#define LOG2_SLOTS 64
#define SUB_BUCKETS 8
#define HIST_SLOTS (LOG2_SLOTS * SUB_BUCKETS)  // 512

struct cfg {
  uint32_t target_dev;
};

static double bucket_mid_us(__u32 idx) {
  __u32 msb = idx / SUB_BUCKETS;
  __u32 sub = idx % SUB_BUCKETS;

  double base = (double)(1ULL << msb);
  // [base,2*base) 구간을 SUB_BUCKETS로 나눈 중앙값
  return base + base * ((double)sub + 0.5) / (double)SUB_BUCKETS;
}

static int get_map_info(int map_fd, struct bpf_map_info* out) {
  __u32 len = sizeof(*out);
  memset(out, 0, sizeof(*out));
  if (bpf_obj_get_info_by_fd(map_fd, out, &len)) return -errno;
  return 0;
}

static uint32_t encode_dev(uint32_t maj, uint32_t min) {
  // kernel new_encode_dev: 12-bit major, 20-bit minor
  return ((maj & 0xfff) << 20) | (min & 0xfffff);
}

static int bump_memlock_rlimit(void) {
  struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
  return setrlimit(RLIMIT_MEMLOCK, &r);
}

static int dev_to_target(const char* path, uint32_t* out_dev_enc,
                         uint32_t* out_maj, uint32_t* out_min) {
  struct stat st;
  if (stat(path, &st) != 0) {
    fprintf(stderr, "stat(%s) failed: %s\n", path, strerror(errno));
    return -1;
  }
  if (!S_ISBLK(st.st_mode)) {
    fprintf(stderr, "%s is not a block device\n", path);
    return -1;
  }
  uint32_t maj = major(st.st_rdev);
  uint32_t min = minor(st.st_rdev);
  if (out_maj) *out_maj = maj;
  if (out_min) *out_min = min;
  *out_dev_enc = encode_dev(maj, min);
  return 0;
}

static int sum_percpu_u64(int map_fd, __u32 key, int ncpu, __u64* out_sum) {
  struct bpf_map_info info;
  int r = get_map_info(map_fd, &info);
  if (r != 0) return r;

  size_t vsize = info.value_size;
  size_t bytes = vsize * (size_t)ncpu;

  void* buf = calloc(1, bytes);
  if (!buf) return -ENOMEM;

  if (bpf_map_lookup_elem(map_fd, &key, buf) != 0) {
    *out_sum = 0;
    free(buf);
    return 0;
  }

  __u64 sum = 0;
  for (int cpu = 0; cpu < ncpu; cpu++) {
    __u64* slot = (__u64*)((char*)buf + vsize * (size_t)cpu);
    sum += *slot;  // 각 percpu 슬롯의 첫 8바이트
  }

  *out_sum = sum;
  free(buf);
  return 0;
}

static uint64_t hist_total_count(int map_fd, int ncpu) {
  uint64_t tot = 0;
  for (__u32 i = 0; i < HIST_SLOTS; i++) {
    __u64 s = 0;
    if (sum_percpu_u64(map_fd, i, ncpu, &s) != 0) continue;
    tot += s;
  }
  return tot;
}

static int percentile_bucket_idx(int map_fd, int ncpu, double p,__u32* out_idx) {
  uint64_t total = hist_total_count(map_fd, ncpu);
  if (total == 0) return -1;

  uint64_t target = (uint64_t)ceil(p * (double)total);
  if (target < 1) target = 1;

  uint64_t cum = 0;
  for (__u32 i = 0; i < HIST_SLOTS; i++) {
    __u64 c = 0;
    if (sum_percpu_u64(map_fd, i, ncpu, &c) != 0) continue;

    cum += c;
    if (cum >= target) {
      *out_idx = i;
      return 0;
    }
  }

  *out_idx = HIST_SLOTS - 1;
  return 0;
}

static int get_global_u64(int map_fd, __u32 key, __u64* out) {
  return bpf_map_lookup_elem(map_fd, &key, out);
}

static void clear_hist(int map_fd, int ncpu) {
  struct bpf_map_info info = {};
  __u32 len = sizeof(info);

  if (bpf_obj_get_info_by_fd(map_fd, &info, &len) != 0) {
    fprintf(stderr, "clear_hist: bpf_obj_get_info_by_fd failed: %s\n",
            strerror(errno));
    return;
  }

  // PERCPU_ARRAY: value_size * ncpu 만큼의 버퍼를 넘겨야 함
  size_t bytes = (size_t)info.value_size * (size_t)ncpu;
  void* zeros = calloc(1, bytes);
  if (!zeros) {
    fprintf(stderr, "clear_hist: calloc failed\n");
    return;
  }

  for (__u32 i = 0; i < HIST_SLOTS; i++) {
    // PERCPU map이면 커널이 bytes 만큼 읽어감 (그래서 zeros는 반드시 bytes여야 안전)
    if (bpf_map_update_elem(map_fd, &i, zeros, BPF_ANY) != 0) {
      // 실패 로그 생략
    }
  }

  free(zeros);
}

static void usage(const char* prog) {
  fprintf(stderr,
          "Usage: %s --dev /dev/nvmeXnY [--interval SEC] [--no-clear]\n"
          "  --dev       target block device (e.g., /dev/nvme1n1)\n"
          "  --interval  print interval seconds (default: 1)\n"
          "  --no-clear  keep cumulative hist (default: clear each interval)\n",
          prog);
}

int main(int argc, char** argv) {
  const char* dev_path = NULL;
  double interval = 1.0;
  bool no_clear = false;

  static const struct option long_opts[] = {
      {"dev", required_argument, NULL, 'd'},
      {"interval", required_argument, NULL, 'i'},
      {"no-clear", no_argument, NULL, 'n'},
      {0, 0, 0, 0}};

  int opt;
  while ((opt = getopt_long(argc, argv, "d:i:n", long_opts, NULL)) != -1) {
    switch (opt) {
      case 'd':
        dev_path = optarg;
        break;
      case 'i':
        interval = atof(optarg);
        break;
      case 'n':
        no_clear = true;
        break;
      default:
        usage(argv[0]);
        return 2;
    }
  }

  if (!dev_path) {
    usage(argv[0]);
    return 2;
  }
  if (interval <= 0) interval = 1.0;

  if (bump_memlock_rlimit() != 0) {
    fprintf(stderr, "Failed to bump RLIMIT_MEMLOCK: %s\n", strerror(errno));
    return 1;
  }

  uint32_t target_dev_enc = 0, maj = 0, min = 0;
  if (dev_to_target(dev_path, &target_dev_enc, &maj, &min) != 0) return 1;

  int ncpu = libbpf_num_possible_cpus();
  if (ncpu < 0) {
    fprintf(stderr, "libbpf_num_possible_cpus failed: %d\n", ncpu);
    return 1;
  }

  struct io_lat_bpf* skel = io_lat_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  // Load
  if (io_lat_bpf__load(skel) != 0) {
    fprintf(stderr, "Failed to load BPF skeleton\n");
    io_lat_bpf__destroy(skel);
    return 1;
  }

  // Configure filter
  uint32_t key0 = 0;
  struct cfg cfg = {
      .target_dev = target_dev_enc,
  };
  int cfg_fd = bpf_map__fd(skel->maps.cfg_map);
  if (bpf_map_update_elem(cfg_fd, &key0, &cfg, BPF_ANY) != 0) {
    fprintf(stderr, "Failed to set cfg_map: %s\n", strerror(errno));
    io_lat_bpf__destroy(skel);
    return 1;
  }

  // Attach (tp_btf)
  skel->links.tp_issue = bpf_program__attach(skel->progs.tp_issue);
  if (!skel->links.tp_issue) {
    fprintf(stderr, "Failed to attach tp_issue: %s\n", strerror(errno));
    io_lat_bpf__destroy(skel);
    return 1;
  }

  skel->links.tp_complete = bpf_program__attach(skel->progs.tp_complete);
  if (!skel->links.tp_complete) {
    fprintf(stderr, "Failed to attach tp_complete: %s\n", strerror(errno));
    io_lat_bpf__destroy(skel);
    return 1;
  }

  // Pin maps for RocksDB access
  const char* pin_dir = "/sys/fs/bpf/rocksdb_io_lat";
  mkdir(pin_dir, 0777); 
  chmod(pin_dir, 0777); // Ensure directory is accessible

  char pin_path[256];
  snprintf(pin_path, sizeof(pin_path), "%s/hist_dev_r_us", pin_dir);
  unlink(pin_path);
  if (bpf_map__pin(skel->maps.hist_dev_r_us, pin_path) != 0) {
    fprintf(stderr, "Failed to pin hist_dev_r_us to %s: %s\n", pin_path, strerror(errno));
  } else {
    chmod(pin_path, 0666); // Allow anyone to read/write this map
    printf("Pinned hist_dev_r_us to %s (perm: 0666)\n", pin_path);
  }

  snprintf(pin_path, sizeof(pin_path), "%s/hist_dev_w_us", pin_dir);
  unlink(pin_path);
  if (bpf_map__pin(skel->maps.hist_dev_w_us, pin_path) != 0) {
    fprintf(stderr, "Failed to pin hist_dev_w_us to %s: %s\n", pin_path, strerror(errno));
  } else {
    chmod(pin_path, 0666);
    printf("Pinned hist_dev_w_us to %s (perm: 0666)\n", pin_path);
  }

  skel->links.tp_insert = bpf_program__attach(skel->progs.tp_insert);
  if (!skel->links.tp_insert) {
    int e = errno;
    fprintf(stderr, "WARN: tp_insert attach failed (optional): %s (%d)\n",
            strerror(e), e);
  }

  int fd_total_r = bpf_map__fd(skel->maps.hist_total_r_us);
  int fd_total_w = bpf_map__fd(skel->maps.hist_total_w_us);
  int fd_wait_r = bpf_map__fd(skel->maps.hist_wait_r_us);
  int fd_wait_w = bpf_map__fd(skel->maps.hist_wait_w_us);
  int fd_dev_r = bpf_map__fd(skel->maps.hist_dev_r_us);
  int fd_dev_w = bpf_map__fd(skel->maps.hist_dev_w_us);
  int fd_hits = bpf_map__fd(skel->maps.prog_hits);
  int fd_inflight = bpf_map__fd(skel->maps.inflight_cnt);
  int fd_wait_r_sum = bpf_map__fd(skel->maps.lat_wait_r_sum);
  int fd_wait_w_sum = bpf_map__fd(skel->maps.lat_wait_w_sum);
  int fd_dev_r_sum = bpf_map__fd(skel->maps.lat_dev_r_sum);
  int fd_dev_w_sum = bpf_map__fd(skel->maps.lat_dev_w_sum);

  printf("Target device: %s (major=%u minor=%u enc=0x%x)\n", dev_path, maj, min,
         target_dev_enc);
  printf("Interval: %.2fs, mode: %s\n", interval,
         no_clear ? "cumulative" : "per-interval");
  printf("Metrics: [p50 p95 p99 p99.9] in microseconds\n");

  if (!no_clear) {
    clear_hist(fd_total_r, ncpu);
    clear_hist(fd_total_w, ncpu);
    clear_hist(fd_wait_r, ncpu);
    clear_hist(fd_wait_w, ncpu);
    clear_hist(fd_dev_r, ncpu);
    clear_hist(fd_dev_w, ncpu);
  }

  while (1) {
    usleep((useconds_t)(interval * 1000000.0));

    uint64_t tr_cnt = hist_total_count(fd_total_r, ncpu);
    uint64_t tw_cnt = hist_total_count(fd_total_w, ncpu);
    uint64_t dr_cnt = hist_total_count(fd_dev_r, ncpu);
    uint64_t dw_cnt = hist_total_count(fd_dev_w, ncpu);
    
    __u64 h0 = 0, h1 = 0, h2 = 0, h3 = 0, inflight = 0;
    __u64 wr_sum = 0, ww_sum = 0, dr_sum = 0, dw_sum = 0;

    sum_percpu_u64(fd_hits, 0, ncpu, &h0);
    sum_percpu_u64(fd_hits, 1, ncpu, &h1);
    sum_percpu_u64(fd_hits, 2, ncpu, &h2);
    sum_percpu_u64(fd_hits, 3, ncpu, &h3);
    get_global_u64(fd_inflight, 0, &inflight);
    sum_percpu_u64(fd_wait_r_sum, 0, ncpu, &wr_sum);
    sum_percpu_u64(fd_wait_w_sum, 0, ncpu, &ww_sum);
    sum_percpu_u64(fd_dev_r_sum, 0, ncpu, &dr_sum);
    sum_percpu_u64(fd_dev_w_sum, 0, ncpu, &dw_sum);

    printf("\n--- [%s] Stats (Req=%llu, Iss=%llu, End=%llu, Miss=%llu) | Current Inflight: %llu ---\n", 
           dev_path, (unsigned long long)h0, (unsigned long long)h1, 
           (unsigned long long)h2, (unsigned long long)h3, (unsigned long long)inflight);

    // Read Stats
    if (dr_cnt > 0 || tr_cnt > 0) {
      __u32 w50 = 0, w95 = 0, w99 = 0, w999 = 0;
      __u32 d50 = 0, d95 = 0, d99 = 0, d999 = 0;
      double w_avg = (double)wr_sum / (double)dr_cnt;
      double d_avg = (double)dr_sum / (double)dr_cnt;

      percentile_bucket_idx(fd_wait_r, ncpu, 0.50, &w50);
      percentile_bucket_idx(fd_wait_r, ncpu, 0.95, &w95);
      percentile_bucket_idx(fd_wait_r, ncpu, 0.99, &w99);
      percentile_bucket_idx(fd_wait_r, ncpu, 0.999, &w999);

      percentile_bucket_idx(fd_dev_r, ncpu, 0.50, &d50);
      percentile_bucket_idx(fd_dev_r, ncpu, 0.95, &d95);
      percentile_bucket_idx(fd_dev_r, ncpu, 0.99, &d99);
      percentile_bucket_idx(fd_dev_r, ncpu, 0.999, &d999);

      printf("%-6s (cnt=%-8llu): wait [avg=%8.1f] ", "READ", (unsigned long long)dr_cnt, w_avg);
      if (hist_total_count(fd_wait_r, ncpu) > 0)
        printf("[%8.1f %8.1f %8.1f %8.1f] ", bucket_mid_us(w50), bucket_mid_us(w95), bucket_mid_us(w99), bucket_mid_us(w999));
      else
        printf("[%8s %8s %8s %8s] ", "0.0", "0.0", "0.0", "0.0");
        
      printf("dev [avg=%8.1f] [%8.1f %8.1f %8.1f %8.1f]\n", d_avg, bucket_mid_us(d50), bucket_mid_us(d95), bucket_mid_us(d99), bucket_mid_us(d999));
    } else {
      printf("%-6s (cnt=0       ): no I/O\n", "READ");
    }

    // Write Stats
    if (dw_cnt > 0 || tw_cnt > 0) {
      __u32 w50 = 0, w95 = 0, w99 = 0, w999 = 0;
      __u32 d50 = 0, d95 = 0, d99 = 0, d999 = 0;
      double w_avg = (double)ww_sum / (double)dw_cnt;
      double d_avg = (double)dw_sum / (double)dw_cnt;

      percentile_bucket_idx(fd_wait_w, ncpu, 0.50, &w50);
      percentile_bucket_idx(fd_wait_w, ncpu, 0.95, &w95);
      percentile_bucket_idx(fd_wait_w, ncpu, 0.99, &w99);
      percentile_bucket_idx(fd_wait_w, ncpu, 0.999, &w999);

      percentile_bucket_idx(fd_dev_w, ncpu, 0.50, &d50);
      percentile_bucket_idx(fd_dev_w, ncpu, 0.95, &d95);
      percentile_bucket_idx(fd_dev_w, ncpu, 0.99, &d99);
      percentile_bucket_idx(fd_dev_w, ncpu, 0.999, &d999);

      printf("%-6s (cnt=%-8llu): wait [avg=%8.1f] ", "WRITE", (unsigned long long)dw_cnt, w_avg);
      if (hist_total_count(fd_wait_w, ncpu) > 0)
        printf("[%8.1f %8.1f %8.1f %8.1f] ", bucket_mid_us(w50), bucket_mid_us(w95), bucket_mid_us(w99), bucket_mid_us(w999));
      else
        printf("[%8s %8s %8s %8s] ", "0.0", "0.0", "0.0", "0.0");

      printf("dev [avg=%8.1f] [%8.1f %8.1f %8.1f %8.1f]\n", d_avg, bucket_mid_us(d50), bucket_mid_us(d95), bucket_mid_us(d99), bucket_mid_us(d999));
    } else {
      printf("%-6s (cnt=0       ): no I/O\n", "WRITE");
    }

    if (!no_clear) {
      clear_hist(fd_total_r, ncpu);
      clear_hist(fd_total_w, ncpu);
      clear_hist(fd_wait_r, ncpu);
      clear_hist(fd_wait_w, ncpu);
      clear_hist(fd_dev_r, ncpu);
      clear_hist(fd_dev_w, ncpu);

      __u64* zeros = calloc(ncpu, sizeof(__u64));
      __u32 k0 = 0;
      bpf_map_update_elem(fd_wait_r_sum, &k0, zeros, BPF_ANY);
      bpf_map_update_elem(fd_wait_w_sum, &k0, zeros, BPF_ANY);
      bpf_map_update_elem(fd_dev_r_sum, &k0, zeros, BPF_ANY);
      bpf_map_update_elem(fd_dev_w_sum, &k0, zeros, BPF_ANY);
      free(zeros);
    }
    fflush(stdout);
  }

  io_lat_bpf__destroy(skel);
  return 0;
}
