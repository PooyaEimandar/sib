/*
 * Copyright (c) 2025 Pooya Eimandar (https://github.com/PooyaEimandar/sib)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <chrono>
#include <folly/coro/BlockingWait.h>
#include <gtest/gtest.h>
#include <sib/database/s_fdb_pool.hpp>

using namespace sib::db;
using namespace std::chrono_literals;

#ifdef __APPLE__
static const std::filesystem::path CLUSTER_FILE = "/usr/local/etc/foundationdb/fdb.cluster";
#else
static const std::filesystem::path CLUSTER_FILE = "/etc/foundationdb/fdb.cluster";
#endif

static constexpr size_t POOL_SIZE = 4;

TEST(SibFDBPool, FoundationDB) {
  auto init_result = s_fdb_pool::init(const_cast<std::filesystem::path&>(CLUSTER_FILE), POOL_SIZE);
  EXPECT_EQ(init_result.has_value() && init_result.value() == 0, true)
    << "Failed to initialize FDB pool";

  EXPECT_EQ(s_fdb_pool::size(), POOL_SIZE)
    << "Invalid pool size, expected " << POOL_SIZE << " but got " << s_fdb_pool::size();

  auto acq_result = folly::coro::blockingWait(s_fdb_pool::acquire(500ms));
  EXPECT_EQ(acq_result.has_value(), true) << "Failed to acquire from FDB pool";

  if (acq_result.has_value()) {
    fdb conn = acq_result.value();
    ASSERT_NE(conn, nullptr);
    EXPECT_GE(s_fdb_pool::in_use(), 1u);
    EXPECT_LE(s_fdb_pool::in_use(), POOL_SIZE);
    s_fdb_pool::release(conn);
  }

  auto fini_result = s_fdb_pool::fini();
  EXPECT_EQ(init_result.has_value() && init_result.value() == 0, true)
    << "Failed to shutdown FDB pool";
}
