#include <folly/io/IOBuf.h>
#include <folly/net/NetworkSocket.h>

#include <proxygen/lib/http/HTTPMessage.h>
#include <proxygen/lib/http/session/HTTPTransaction.h>

#include <sib/network/s_proxygen_server.hpp>
#include <sib/sib.hpp>

using namespace sib::network::http;

constexpr auto MAX_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB
constexpr auto* SERVER_NAME = "SIB";

struct json_handler : public proxygen::HTTPTransaction::Handler {
  void onHeadersComplete(std::unique_ptr<proxygen::HTTPMessage> p_headers) noexcept override {
    if (p_headers->getMethod() == proxygen::HTTPMethod::GET) {
      static constexpr auto* content_type = "application/json";
      static constexpr auto* content_length = "27";
      static constexpr std::string_view kJsonPayload{R"({"message":"Hello, World!"})"};

      proxygen::HTTPMessage response;
      response.setStatusCode(200);
      response.setStatusMessage("OK");
      response.setIsChunked(false);
      response.setWantsKeepalive(false);

      auto& headers = response.getHeaders();
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_SERVER, SERVER_NAME);
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_TYPE, content_type);
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_LENGTH, content_length);

      _txn->sendHeaders(response);
      static const auto kJsonBuf =
        folly::IOBuf::wrapBufferAsValue(kJsonPayload.data(), kJsonPayload.size());
      _txn->sendBody(kJsonBuf.clone());
      _txn->sendEOM();
    }
  }

  void onBody(std::unique_ptr<folly::IOBuf>) noexcept override {}
  void onTrailers(std::unique_ptr<proxygen::HTTPHeaders>) noexcept override {}
  void onUpgrade(proxygen::UpgradeProtocol) noexcept override {}
  void onError(const proxygen::HTTPException&) noexcept override {}
  void onEgressPaused() noexcept override {}
  void onEgressResumed() noexcept override {}
  void setTransaction(proxygen::HTTPTransaction* txn) noexcept override { _txn = txn; }
  void detachTransaction() noexcept override { _txn = nullptr; }
  void onEOM() noexcept override {}
  proxygen::HTTPTransaction* _txn{nullptr};
};

struct plain_text_handler : public proxygen::HTTPTransaction::Handler {
  void onHeadersComplete(std::unique_ptr<proxygen::HTTPMessage> p_headers) noexcept override {
    if (p_headers->getMethod() == proxygen::HTTPMethod::GET) {
      static constexpr auto* content_type = "text/plain";
      static constexpr auto* content_length = "13";
      static constexpr std::string_view kPlainPayload{"Hello, World!"};

      proxygen::HTTPMessage response;
      response.setStatusCode(200);
      response.setStatusMessage("OK");
      response.setIsChunked(false);
      response.setWantsKeepalive(false);

      auto& headers = response.getHeaders();
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_SERVER, SERVER_NAME);
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_TYPE, content_type);
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_LENGTH, content_length);

      _txn->sendHeaders(response);
      static const auto kPlainBuf =
        folly::IOBuf::wrapBufferAsValue(kPlainPayload.data(), kPlainPayload.size());
      _txn->sendBody(kPlainBuf.clone());
      _txn->sendEOM();
    }
  }

  void onBody(std::unique_ptr<folly::IOBuf>) noexcept override {}
  void onTrailers(std::unique_ptr<proxygen::HTTPHeaders>) noexcept override {}
  void onUpgrade(proxygen::UpgradeProtocol) noexcept override {}
  void onError(const proxygen::HTTPException&) noexcept override {}
  void onEgressPaused() noexcept override {}
  void onEgressResumed() noexcept override {}
  void setTransaction(proxygen::HTTPTransaction* txn) noexcept override { _txn = txn; }
  void detachTransaction() noexcept override { _txn = nullptr; }
  void onEOM() noexcept override {}
  proxygen::HTTPTransaction* _txn{nullptr};
};

auto create_socket_opt() {
  using ApplyPos = folly::SocketOptionKey::ApplyPos;
  folly::SocketOptionMap socket_opt{};
  // Enable SO_REUSEADDR, this is important for the server to be able to restart quickly
  socket_opt.emplace(
    folly::SocketOptionKey{SOL_SOCKET, SO_REUSEADDR, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1});

  // Disable Nagle (reduce latency)
  socket_opt.emplace(
    folly::SocketOptionKey{IPPROTO_TCP, TCP_NODELAY, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1});
  socket_opt.emplace(
    folly::SocketOptionKey{IPPROTO_TCP, TCP_NODELAY, ApplyPos::POST_BIND},
    folly::SocketOptionValue{1});
  socket_opt.emplace(
    folly::SocketOptionKey{
      IPPROTO_TCP, TCP_NOTSENT_LOWAT, folly::SocketOptionKey::ApplyPos::POST_BIND},
    folly::SocketOptionValue{1});

  // Increase socket buffers (avoid drops under load)
  socket_opt.emplace(
    folly::SocketOptionKey{SOL_SOCKET, SO_RCVBUF, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{MAX_BUFFER_SIZE});
  socket_opt.emplace(
    folly::SocketOptionKey{SOL_SOCKET, SO_SNDBUF, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{MAX_BUFFER_SIZE});

// Linux only TCP fast open for reducing handshake overhead
#ifdef __linux__
  socket_opt.emplace(
    folly::SocketOptionKey{SOL_SOCKET, SO_REUSEPORT, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1});
  socket_opt.emplace(
    folly::SocketOptionKey{IPPROTO_TCP, TCP_FASTOPEN, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1000} // Queue length for TFO
  );
#else
  socket_opt.emplace(
    folly::SocketOptionKey{IPPROTO_TCP, TCP_NOOPT, folly::SocketOptionKey::ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1});
#endif

  return socket_opt;
}

int main(int argc, char* argv[]) {
  std::span<char*> argv_span(argv, argc);
  const auto result = sib::init(argc, argv_span);
  assert(result.hasValue());

  const auto num_threads = std::thread::hardware_concurrency();

  proxygen::HTTPServerOptions opts;
  opts.threads = num_threads;
  opts.shutdownOn = {SIGINT};
  opts.idleTimeout = std::chrono::milliseconds(15000);
  opts.enableContentCompression = false;
  opts.h2cEnabled = false;
  opts.listenBacklog = 65535;
  opts.maxConcurrentIncomingStreams = 1000;
  opts.initialReceiveWindow = 512 * 1024;
  opts.receiveStreamWindowSize = 512 * 1024;
  opts.receiveSessionWindowSize = MAX_BUFFER_SIZE;
  opts.useZeroCopy = true;
  opts.enableExHeaders = false;

  std::vector<proxygen::HTTPServer::IPConfig> ip_configs = {
    {folly::SocketAddress("0.0.0.0", 8080), proxygen::HTTPServer::Protocol::HTTP, nullptr}};
  ip_configs[0].enableTCPFastOpen = true;
  ip_configs[0].acceptorSocketOptions = create_socket_opt();

  s_h_server h(std::move(opts));
  h.set_domains({"localhost"}).set_alpn_protocols({"http/1.1"}).set_ips(std::move(ip_configs));

  auto server = s_proxygen_server::make()->set_num_threads(num_threads)->set_h(std::move(h));

  server->run_forever([](proxygen::HTTPMessage* req) -> proxygen::HTTPTransactionHandler* {
    static thread_local json_handler json;
    static thread_local plain_text_handler text;

    if (req->getPath() == "/json") {
      return &json;
    }

    return &text;
  });

  return 0;
}