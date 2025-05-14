/*
  Mozilla Public License 2.0 (MPL-2.0)

  This file is part of the "https://github.com/PooyaEimandar/sib" project, which is licensed under
  the MPL-2.0. You can obtain a copy of the license at: https://opensource.org/licenses/MPL-2.0

  The MPL-2.0 allows you to use, modify, and distribute this file under certain conditions.
  The source code may be modified and distributed, provided that you retain the same license
  and include a copy of this notice when redistributing the code.

  This project was created by Pooya Eimandar.

  For more information on the terms of this license, please refer to the official MPL-2.0
  documentation.

  SPDX-License-Identifier: MPL-2.0
*/

#pragma once

#include <folly/coro/BlockingWait.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <chrono>
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
  folly::ScopedEventBaseThread eb_thread;
  folly::EventBase* evb = eb_thread.getEventBase();
  auto timekeeper = std::make_shared<folly::ThreadWheelTimekeeper>();

  auto init_result = s_fdb_pool::init(const_cast<std::filesystem::path&>(CLUSTER_FILE), POOL_SIZE);
  EXPECT_EQ(init_result.hasValue() && init_result.value() == 0, true)
    << "Failed to initialize FDB pool";

  EXPECT_EQ(s_fdb_pool::size(), POOL_SIZE)
    << "Invalid pool size, expected " << POOL_SIZE << " but got " << s_fdb_pool::size();

  auto acq_result =
    folly::coro::blockingWait(s_fdb_pool::acquire(500ms, timekeeper.get()).scheduleOn(evb));

  if (acq_result.hasValue()) {
    fdb conn = acq_result.value();
    ASSERT_NE(conn, nullptr);
    EXPECT_GE(s_fdb_pool::in_use(), 1u);
    EXPECT_LE(s_fdb_pool::in_use(), POOL_SIZE);
    s_fdb_pool::release(conn);
  }

  auto fini_result = s_fdb_pool::fini();
  EXPECT_EQ(init_result.hasValue() && init_result.value() == 0, true)
    << "Failed to shutdown FDB pool";
}
