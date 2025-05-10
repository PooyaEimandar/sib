/*
 * Copyright (c) WolfSource (https://github.com/wolfsource/wolf). All rights reserved.
 */

#pragma once

#include <chrono>
#include <folly/coro/BlockingWait.h>
#include <gtest/gtest.h>
#include <wolf/database/w_fdb_pool.hpp>

using namespace wolf::db;
using namespace std::chrono_literals;

#ifdef __APPLE__
static const std::filesystem::path CLUSTER_FILE = "/usr/local/etc/foundationdb/fdb.cluster";
#else
static const std::filesystem::path CLUSTER_FILE = "/etc/foundationdb/fdb.cluster";
#endif

static constexpr size_t POOL_SIZE = 4;

TEST(WolfFDBPool, FoundationDB) {
  auto init_result = w_fdb_pool::init(const_cast<std::filesystem::path&>(CLUSTER_FILE), POOL_SIZE);
  EXPECT_EQ(init_result.has_value() && init_result.value() == 0, true)
    << "Failed to initialize FDB pool";

  EXPECT_EQ(w_fdb_pool::size(), POOL_SIZE)
    << "Invalid pool size, expected " << POOL_SIZE << " but got " << w_fdb_pool::size();

  auto acq_result = folly::coro::blockingWait(w_fdb_pool::acquire(500ms));
  EXPECT_EQ(acq_result.has_value(), true) << "Failed to acquire from FDB pool";

  if (acq_result.has_value()) {
    fdb conn = acq_result.value();
    ASSERT_NE(conn, nullptr);
    EXPECT_GE(w_fdb_pool::in_use(), 1u);
    EXPECT_LE(w_fdb_pool::in_use(), POOL_SIZE);
    w_fdb_pool::release(conn);
  }

  auto fini_result = w_fdb_pool::fini();
  EXPECT_EQ(init_result.has_value() && init_result.value() == 0, true)
    << "Failed to shutdown FDB pool";
}
