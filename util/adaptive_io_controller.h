//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <atomic>
#include <thread>
#include <string>
#include "rocksdb/rate_limiter.h"
#include "util/bpf_latency_reader.h"

namespace ROCKSDB_NAMESPACE {

class AdaptiveIoController {
 public:
  AdaptiveIoController(RateLimiter* rate_limiter, 
                       uint64_t latency_threshold_us,
                       const std::string& bpf_map_path);
  ~AdaptiveIoController();

  Status Start();
  void Stop();

 private:
  void ControlLoop();

  RateLimiter* rate_limiter_;
  uint64_t latency_threshold_us_;
  std::string bpf_map_path_;
  BpfLatencyReader reader_;
  
  std::atomic<bool> stop_;
  std::thread thread_;

  int64_t current_rate_bps_;
  int64_t max_rate_bps_;
  static const int64_t kMinRateBps = 1 * 1024 * 1024; // 1MB/s
  static const int64_t kAdditiveIncreaseBps = 10 * 1024 * 1024; // 10MB/s
};

}  // namespace ROCKSDB_NAMESPACE
