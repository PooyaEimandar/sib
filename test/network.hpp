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

#include <gtest/gtest.h>

#include <sib/sib.hpp>

#ifdef SIB_NET_PROXYGEN

#include <sib/network/s_proxygen_server.hpp>

// NOLINTBEGIN (modernize-use-trailing-return-type)

using s_proxygen_server = sib::network::http::s_proxygen_server;
using s_h2_server = sib::network::http::s_h2_server;

TEST(SibHttpServerTest, NeitherH2NorH3ReturnsError) {
  proxygen::HTTPServerOptions opts;
  opts.threads = 1;
  opts.shutdownOn = {SIGINT};

  std::vector<proxygen::HTTPServer::IPConfig> ip_configs = {
    {folly::SocketAddress("127.0.0.1", 8443), proxygen::HTTPServer::Protocol::HTTP2, nullptr}};

  // Configure H2 server
  s_h2_server h2(std::move(opts));
  h2.set_domains({"localhost"})
    .set_chain("")
    .set_cert("")
    .set_key("")
    .set_ips(std::move(ip_configs));

  auto result =
    s_proxygen_server::make()
      ->set_num_threads(1)
      ->set_h2(std::move(h2))
      ->run_forever([](proxygen::HTTPMessage*) -> proxygen::HTTPTransactionHandler* {
        return nullptr; // No-op request handler
      });

  EXPECT_TRUE(result.hasError());
}

// NOLINTEND

#endif // SIB_NET_PROXYGEN