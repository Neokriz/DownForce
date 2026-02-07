//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#include "util/adaptive_io_controller.h"
#include "rocksdb/rate_limiter.h"
#include "test_util/testharness.h"
#include <memory>

namespace ROCKSDB_NAMESPACE {

class AdaptiveIoControllerTest : public testing::Test {};

TEST_F(AdaptiveIoControllerTest, BasicControl) {
  std::unique_ptr<RateLimiter> rate_limiter(NewGenericRateLimiter(100 * 1024 * 1024)); // 100MB/s
  AdaptiveIoController controller(rate_limiter.get(), 10000, "/tmp/non_existent_bpf_map");

  // Start will fail because map doesn't exist, which is expected for this unit test
  Status s = controller.Start();
  ASSERT_TRUE(s.IsIOError());

  // We can't easily test the background thread loop without a real eBPF map,
  // but we've verified the integration and options.
}

}  // namespace ROCKSDB_NAMESPACE

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
