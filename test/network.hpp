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

#include <sib/network/s_proxygen_server.hpp>
#include <sib/sib.hpp>

// NOLINTBEGIN (modernize-use-trailing-return-type)

using s_proxygen_server = sib::network::http::s_proxygen_server;

// TEST(SibHttpServerTest, NeitherH2NorH3ReturnsError) {
//   auto server = s_proxygen_server::make();

//   auto result = server->run_forever(
//     [](proxygen::HTTPMessage*) -> proxygen::HTTPTransactionHandler* { return nullptr; });
//   EXPECT_TRUE(result.hasError());
// }

// TEST(HttpServerTest, StartsAndRespondsH2) {
//   proxygen::HTTPServerOptions h2_opt{};
//   folly::SocketAddress addr("::1", 8080);
//   auto ip_configs = std::vector<proxygen::HTTPServer::IPConfig>{
//     {addr, proxygen::HTTPServer::Protocol::HTTP2, nullptr}};

//   auto h2_server = sib::network::http::s_h2_server(std::move(h2_opt));

//   // h2_server = std::move(h2_server.set_domains({"localhost"}).set_ips(std::move(ip_configs)));

//   // // Setup server
//   // auto result =
//   //   s_server::make()
//   //     ->set_h2(std::move(h2_server))
//   //     .set_num_threads(1)
//   //     .run_forever([](proxygen::HTTPMessage*) -> proxygen::HTTPTransactionHandler* {
//   //       return nullptr;
//   //     });

//   // EXPECT_TRUE(result.hasValue());
// }

// NOLINTEND