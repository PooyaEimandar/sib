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

#include <iostream>

#include <folly/Benchmark.h>
#include <folly/coro/BlockingWait.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#ifdef SIB_DB_FDB

#include <sib/database/s_fdb_pool.hpp>
#include <sib/system/s_trace.hpp>

using namespace sib::db;
using namespace std::chrono_literals;

auto fdb_pool_init() {
  static constexpr size_t BENCH_POOL_SIZE = 4;
#ifdef __APPLE__
  static const std::filesystem::path CLUSTER_FILE = "/usr/local/etc/foundationdb/fdb.cluster";
#else
  static const std::filesystem::path CLUSTER_FILE = "/etc/foundationdb/fdb.cluster";
#endif
  return s_fdb_pool::init(const_cast<std::filesystem::path&>(CLUSTER_FILE), BENCH_POOL_SIZE);
}

auto fdb_pool_fini() {
  return s_fdb_pool::fini();
}

BENCHMARK(fdb_pool_init_bench) {
  TRY(fdb_pool_init());
  TRY(fdb_pool_fini());
}

BENCHMARK(fdb_pool_acquire_release_bench) {
  static folly::ScopedEventBaseThread evb_thread;
  static folly::EventBase* evb = evb_thread.getEventBase();
  static auto tk = std::make_shared<folly::ThreadWheelTimekeeper>();
  static bool initialized = false;

  if (!initialized) {
    fdb_pool_init();
    initialized = true;
  }

  auto res = folly::coro::blockingWait(s_fdb_pool::acquire(100ms, tk.get()).scheduleOn(evb));
  if (res.hasError()) {
    std::cerr << "Error acquiring fdb pool: " << res.error() << std::endl;
    return;
  }
  s_fdb_pool::release(*res);
}

#endif // SIB_DB_FDB