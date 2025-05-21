#include <folly/net/NetworkSocket.h>
#include <proxygen/lib/http/HTTPMessage.h>
#include <proxygen/lib/http/session/HTTPTransaction.h>

#include <sib/network/s_proxygen_server.hpp>
#include <sib/sib.hpp>

using namespace sib::network::http;

constexpr auto MAX_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB

struct plain_text_handler : public proxygen::HTTPTransaction::Handler {
  virtual void onHeadersComplete(
    std::unique_ptr<proxygen::HTTPMessage> p_headers) noexcept override {
    if (p_headers->getMethod() == proxygen::HTTPMethod::GET) {
      constexpr auto* plain_text = "text/plain";
      constexpr auto* body = "Hello from Sib!";
      constexpr auto* body_len_str = "15";
      static const auto body_len = strlen(body);

      proxygen::HTTPMessage response;
      response.setStatusCode(200);
      response.setStatusMessage("OK");
      response.setIsChunked(false);
      response.setWantsKeepalive(true);

      auto& headers = response.getHeaders();
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_TYPE, plain_text);
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_LENGTH, body_len_str);

      _txn->sendHeaders(response);

      _txn->sendBody(std::move(folly::IOBuf::wrapBuffer(body, body_len)));
      _txn->sendEOM();
    }
  }
  virtual void onBody([[maybe_unused]] std::unique_ptr<folly::IOBuf> p_chain) noexcept override {}
  virtual void onTrailers(
    [[maybe_unused]] std::unique_ptr<proxygen::HTTPHeaders> p_trailers) noexcept override {}
  virtual void onUpgrade([[maybe_unused]] proxygen::UpgradeProtocol p_protocol) noexcept override {}
  virtual void onError(const proxygen::HTTPException& p_error) noexcept override {}
  virtual void onEgressPaused() noexcept override {}
  virtual void onEgressResumed() noexcept override {}
  void setTransaction(proxygen::HTTPTransaction* p_txn) noexcept override { _txn = p_txn; }
  void detachTransaction() noexcept override { delete this; }
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
#endif

  return socket_opt;
}

auto main(int p_argc, char* p_argv[]) -> int {
  // Initialize Sib
  std::span<char*> argv_span(p_argv, p_argc);
  const auto result = sib::init(p_argc, argv_span);
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
  opts.initialReceiveWindow = 512 * 1024; // 512KB
  opts.receiveStreamWindowSize = 512 * 1024;
  opts.receiveSessionWindowSize = MAX_BUFFER_SIZE; // per session
  opts.useZeroCopy = true;
  opts.enableExHeaders = false;

  std::vector<proxygen::HTTPServer::IPConfig> ip_configs = {
    {folly::SocketAddress("0.0.0.0", 8080), proxygen::HTTPServer::Protocol::HTTP, nullptr}};
  ip_configs[0].enableTCPFastOpen = true;
  ip_configs[0].acceptorSocketOptions = std::move(create_socket_opt());

  // Configure server
  s_h_server h(std::move(opts));
  h.set_domains({"localhost"}).set_alpn_protocols({"http/1.1"}).set_ips(std::move(ip_configs));

  auto server = s_proxygen_server::make()->set_num_threads(num_threads)->set_h(std::move(h));

  server->run_forever(
    []([[maybe_unused]] proxygen::HTTPMessage* p_req) -> proxygen::HTTPTransactionHandler* {
      return new plain_text_handler();
    });

  return 0;
}