//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include "util/adaptive_io_controller.h"
#include <chrono>
#include <algorithm>
#include <iostream>

namespace ROCKSDB_NAMESPACE {

AdaptiveIoController::AdaptiveIoController(RateLimiter* rate_limiter, 
                                           uint64_t latency_threshold_us,
                                           const std::string& bpf_map_path)
    : rate_limiter_(rate_limiter),
      latency_threshold_us_(latency_threshold_us),
      bpf_map_path_(bpf_map_path),
      stop_(false) {
  max_rate_bps_ = rate_limiter_->GetBytesPerSecond();
  current_rate_bps_ = max_rate_bps_;
}

AdaptiveIoController::~AdaptiveIoController() {
  Stop();
}

Status AdaptiveIoController::Start() {
  Status s = reader_.Open(bpf_map_path_);
  if (!s.ok()) {
    return s;
  }

  stop_ = false;
  thread_ = std::thread(&AdaptiveIoController::ControlLoop, this);
  return Status::OK();
}

void AdaptiveIoController::Stop() {
  if (thread_.joinable()) {
    stop_ = true;
    thread_.join();
  }
}

void AdaptiveIoController::ControlLoop() {
  while (!stop_) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    uint64_t p99_us = 0;
    Status s = reader_.GetP99Latency(&p99_us);
    if (!s.ok()) {
      continue;
    }

    if (p99_us == 0) {
      // No I/O activity detected, maybe increase rate slightly or keep as is
      continue;
    }

    int64_t new_rate = current_rate_bps_;
    if (p99_us > latency_threshold_us_) {
      // Multiplicative Decrease (reduce by 20%)
      new_rate = static_cast<int64_t>(static_cast<double>(current_rate_bps_) * 0.8);
    } else {
      // Additive Increase
      new_rate = current_rate_bps_ + kAdditiveIncreaseBps;
    }

    // Clamp values
    new_rate = std::max(kMinRateBps, std::min(max_rate_bps_, new_rate));

    if (new_rate != current_rate_bps_) {
      current_rate_bps_ = new_rate;
      rate_limiter_->SetBytesPerSecond(current_rate_bps_);
    }
  }
}

}  // namespace ROCKSDB_NAMESPACE
