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

// #ifdef SIB_NET_HTTP

#pragma once

#include <filesystem>
#include <sib/sib.hpp>

#include <proxygen/httpserver/samples/hq/HQCommandLine.h>
// #include <proxygen/httpserver/HTTPServer.h>
// #include <proxygen/httpserver/samples/hq/ConnIdLogger.h>
// #include <proxygen/httpserver/samples/hq/HQParams.h>
// #include <proxygen/httpserver/samples/hq/HQServer.h>
// #include <proxygen/lib/http/session/HQSession.h>

struct h3_server {
 private:
  quic::samples::HQToolServerParams param_{};
};

struct h2_server {
 private:
  std::optional<uint16_t> port_;
};

struct s_http_server {
 private:
  std::optional<h2_server> h2_;
  std::optional<h3_server> h3_;
  std::optional<std::filesystem::path> chain_path_;
  std::optional<std::filesystem::path> cert_path_;
  std::optional<std::filesystem::path> key_path_;
};

// #endif // SIB_NET_HTTP
