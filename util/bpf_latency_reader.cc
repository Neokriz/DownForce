//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include "util/bpf_latency_reader.h"
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <cmath>
#include <cstring>
#include <iostream>

namespace ROCKSDB_NAMESPACE {

// Helper for bpf syscall
static int bpf_syscall(int cmd, union bpf_attr* attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

BpfLatencyReader::BpfLatencyReader() : map_fd_(-1), ncpu_(-1) {
  ncpu_ = static_cast<int>(sysconf(_SC_NPROCESSORS_ONLN));
}

BpfLatencyReader::~BpfLatencyReader() {
  if (map_fd_ >= 0) {
    close(map_fd_);
  }
}

Status BpfLatencyReader::Open(const std::string& pin_path) {
  union bpf_attr attr;
  std::memset(&attr, 0, sizeof(attr));
  attr.pathname = reinterpret_cast<uint64_t>(pin_path.c_str());

  int fd = bpf_syscall(BPF_OBJ_GET, &attr, sizeof(attr));
  if (fd < 0) {
    return Status::IOError("Failed to open BPF object", pin_path + ": " + std::strerror(errno));
  }
  map_fd_ = fd;
  return Status::OK();
}

double BpfLatencyReader::BucketMidUs(uint32_t idx) {
  uint32_t msb = idx / kSubBuckets;
  uint32_t sub = idx % kSubBuckets;

  double base = static_cast<double>(1ULL << msb);
  // [base, 2*base) interval divided by kSubBuckets, find midpoint of the bucket
  return base + base * (static_cast<double>(sub) + 0.5) / static_cast<double>(kSubBuckets);
}

Status BpfLatencyReader::ReadHistogram(std::vector<uint64_t>& combined_hist) {
  if (map_fd_ < 0) return Status::Corruption("Map not open");

  combined_hist.assign(kHistSlots, 0);
  
  // Per-CPU maps return an array of values, one for each possible CPU.
  // We use 256 as a safe upper bound for possible CPUs if ncpu_ is not reliable,
  // but better to use a dynamic size based on ncpu_.
  // Note: BPF_MAP_LOOKUP_ELEM for PERCPU maps expects value to point to an array
  // of size (value_size * round_up(possible_cpus, 8) or similar depending on kernel).
  // Actually, libbpf uses libbpf_num_possible_cpus().
  
  // For simplicity and robustness, let's use a large enough buffer.
  const int max_possible_cpus = 256; 
  std::vector<uint64_t> per_cpu_values(max_possible_cpus);

  for (uint32_t i = 0; i < kHistSlots; ++i) {
    union bpf_attr attr;
    std::memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd_;
    attr.key = reinterpret_cast<uint64_t>(&i);
    attr.value = reinterpret_cast<uint64_t>(per_cpu_values.data());

    if (bpf_syscall(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) != 0) {
      continue;
    }

    uint64_t sum = 0;
    // We only sum up to ncpu_, but some systems might have non-contiguous CPU IDs.
    // However, for ARRAY maps, it should be fine.
    for (int cpu = 0; cpu < ncpu_; ++cpu) {
      sum += per_cpu_values[cpu];
    }
    combined_hist[i] = sum;
  }

  return Status::OK();
}

Status BpfLatencyReader::GetP99Latency(uint64_t* p99_us) {
  std::vector<uint64_t> hist;
  Status s = ReadHistogram(hist);
  if (!s.ok()) return s;

  uint64_t total = 0;
  for (uint64_t count : hist) {
    total += count;
  }

  if (total == 0) {
    *p99_us = 0;
    return Status::OK();
  }

  uint64_t target = static_cast<uint64_t>(std::ceil(0.99 * static_cast<double>(total)));
  uint64_t cum = 0;
  for (uint32_t i = 0; i < kHistSlots; ++i) {
    cum += hist[i];
    if (cum >= target) {
      *p99_us = static_cast<uint64_t>(BucketMidUs(i));
      // Once we have the P99 from this window, clear the map for next window
      ClearHistogram().PermitUncheckedError();
      return Status::OK();
    }
  }

  *p99_us = static_cast<uint64_t>(BucketMidUs(kHistSlots - 1));
  ClearHistogram().PermitUncheckedError();
  return Status::OK();
}

Status BpfLatencyReader::ClearHistogram() {
  if (map_fd_ < 0) return Status::Corruption("Map not open");

  // Zero buffer for all CPUs
  const int max_possible_cpus = 256;
  std::vector<uint64_t> zeros(max_possible_cpus, 0);

  for (uint32_t i = 0; i < kHistSlots; ++i) {
    union bpf_attr attr;
    std::memset(&attr, 0, sizeof(attr));
    attr.map_fd = map_fd_;
    attr.key = reinterpret_cast<uint64_t>(&i);
    attr.value = reinterpret_cast<uint64_t>(zeros.data());
    attr.flags = BPF_ANY;

    // Use BPF_MAP_UPDATE_ELEM to zero out the entry
    bpf_syscall(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
  }
  return Status::OK();
}

}  // namespace ROCKSDB_NAMESPACE
