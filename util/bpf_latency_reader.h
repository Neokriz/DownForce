//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <stdint.h>
#include <string>
#include <vector>
#include "rocksdb/status.h"

namespace ROCKSDB_NAMESPACE {

class BpfLatencyReader {
 public:
  BpfLatencyReader();
  ~BpfLatencyReader();

  // Open the pinned BPF map
  Status Open(const std::string& pin_path);

  // Read the histogram and calculate P99 latency in microseconds
  Status GetP99Latency(uint64_t* p99_us);

  // Clear the histogram data in BPF map
  Status ClearHistogram();

 private:
  int map_fd_;
  int ncpu_;
  
  // Histogram config matching ebpf program
  static const int kLog2Slots = 64;
  static const int kSubBuckets = 8;
  static const int kHistSlots = kLog2Slots * kSubBuckets;

  double BucketMidUs(uint32_t idx);
  Status ReadHistogram(std::vector<uint64_t>& combined_hist);
};

}  // namespace ROCKSDB_NAMESPACE
