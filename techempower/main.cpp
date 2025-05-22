#include <folly/io/IOBuf.h>
#include <folly/net/NetworkSocket.h>

#include <proxygen/lib/http/HTTPMessage.h>
#include <proxygen/lib/http/session/HTTPTransaction.h>

#include <sib/network/s_proxygen_server.hpp>
#include <sib/sib.hpp>

using namespace sib::network::http;

constexpr auto MAX_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB
constexpr auto* SERVER_NAME = "SIB";

// constexpr
constexpr std::string_view k_json_payload{R"({"message":"Hello, World!"})"};
constexpr std::string_view k_plain_payload{"Hello, World!"};
constexpr auto k_json_payload_size = "27";
constexpr auto k_plain_payload_size = "13";
static const auto k_json_buf =
  folly::IOBuf::wrapBufferAsValue(k_json_payload.data(), k_json_payload.size());
static const auto k_plain_buf =
  folly::IOBuf::wrapBufferAsValue(k_plain_payload.data(), k_plain_payload.size());

struct handler : public proxygen::HTTPTransaction::Handler {
  explicit handler(const proxygen::HTTPMessage& p_headers, const folly::IOBuf& p_buffer)
    : headers_(p_headers), buffer_(p_buffer) {}

  void onHeadersComplete(
    [[maybe_unused]] std::unique_ptr<proxygen::HTTPMessage> p_req) noexcept override {
    txn_->sendHeaders(headers_);
    txn_->sendBody(buffer_.cloneOne());
    txn_->sendEOM();
  }

  void onBody(std::unique_ptr<folly::IOBuf>) noexcept override {}
  void onTrailers(std::unique_ptr<proxygen::HTTPHeaders>) noexcept override {}
  void onUpgrade(proxygen::UpgradeProtocol) noexcept override {}
  void onError(const proxygen::HTTPException&) noexcept override {}
  void onEgressPaused() noexcept override {}
  void onEgressResumed() noexcept override {}
  void setTransaction(proxygen::HTTPTransaction* p_txn) noexcept override { txn_ = p_txn; }
  void detachTransaction() noexcept override { txn_ = nullptr; }
  void onEOM() noexcept override {}

 private:
  proxygen::HTTPTransaction* txn_{nullptr};
  const proxygen::HTTPMessage& headers_;
  const folly::IOBuf& buffer_;
};

auto create_socket_opt() -> folly::SocketOptionMap {
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

auto make_response_headers(folly::StringPiece p_content_type, folly::StringPiece p_len)
  -> proxygen::HTTPMessage {
  proxygen::HTTPMessage response;
  response.setStatusCode(200);
  response.setStatusMessage("OK");
  response.setIsChunked(false);
  response.setWantsKeepalive(false);

  auto& h = response.getHeaders();
  h.add(proxygen::HTTPHeaderCode::HTTP_HEADER_SERVER, SERVER_NAME);
  h.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_TYPE, p_content_type);
  h.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_LENGTH, p_len);

  return response;
}

int main(int p_argc, char** p_argv) {
  std::span<char*> argv_span(p_argv, p_argc);
  sib::init(p_argc, argv_span);

  proxygen::HTTPServerOptions opts;
  opts.threads = 0;
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

  auto server = s_proxygen_server::make()->set_h(std::move(h));

  server->run_forever([](proxygen::HTTPMessage* p_req) -> proxygen::HTTPTransactionHandler* {
    thread_local static auto json_headers =
      make_response_headers("application/json", k_json_payload_size);
    thread_local static auto text_headers =
      make_response_headers("text/plain", k_plain_payload_size);
    thread_local static handler json_handler(json_headers, k_json_buf);
    thread_local static handler text_handler(text_headers, k_plain_buf);

    if (p_req->getPath() == "/json") {
      return &json_handler;
    }
    return &text_handler;
  });
}
