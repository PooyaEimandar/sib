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

#include <folly/Benchmark.h>
#include <folly/coro/BlockingWait.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <sib/database/s_fdb_pool.hpp>
#include <sib/system/s_trace.hpp>

#include <iostream>

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
  boost::leaf::try_handle_all(
    []() -> boost::leaf::result<int> {
      BOOST_LEAF_CHECK(fdb_pool_init());
      BOOST_LEAF_CHECK(fdb_pool_fini());
      return {};
    },
    [](const sib::system::s_trace& p_trace) {
      std::cerr << "got leaf exception: " << p_trace << "\n";
      return 1;
    },
    [](const std::exception& p_exc) {
      std::cerr << "got an exception: " << p_exc.what() << "\n";
      return 1;
    },
    []() {
      std::cerr << "got an unknown exception" << "\n";
      return 1;
    });
}

// BENCHMARK(fdb_pool_acquire_release_bench) {
//   static folly::ScopedEventBaseThread evb_thread;
//   static folly::EventBase* evb = evb_thread.getEventBase();
//   static auto tk = std::make_shared<folly::ThreadWheelTimekeeper>();
//   static bool initialized = false;

//   if (!initialized) {
//     fdb_pool_init();
//     initialized = true;
//   }

//   auto result = folly::coro::blockingWait(s_fdb_pool::acquire(100ms, tk.get()).scheduleOn(evb));
//   if (!result.has_value()) {
//     XLOG(FATAL) << "Failed to acquire from FDB pool";
//   }

//   s_fdb_pool::release(*result);
// }