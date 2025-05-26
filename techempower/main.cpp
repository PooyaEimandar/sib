#include <seastar/core/app-template.hh>
#include <seastar/http/httpd.hh>
#include <seastar/http/function_handlers.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/reactor.hh>
#include <iostream>

using namespace seastar;
using namespace seastar::httpd;

int main(int argc, char** argv) {
    app_template app;
    auto server = std::make_shared<http_server_control>();

    return app.run(argc, argv, [server] () -> future<> {
        constexpr auto port = 8080;
        constexpr auto server_name = "Sib HTTP Server";

        return server->start(server_name).then([server] {
            return server->set_routes([] (routes& p_routes) {
                p_routes.add(operation_type::GET, url("/plaintext"),
                    new function_handler(
                        [] (std::unique_ptr<http::request> p_req,
                            std::unique_ptr<http::reply> p_rep)
                        -> future<std::unique_ptr<http::reply>> {
                            p_rep->add_header("Server", "Sib");
                            p_rep->set_status(http::reply::status_type::ok);
                            p_rep->write_body("text/plain", "Hello, World!");
                            return make_ready_future<std::unique_ptr<http::reply>>(std::move(p_rep));
                        },
                        "text"
                    )
                );
            });
        }).then([server, port] {
            return server->listen(socket_address{ipv4_addr{port}});
        }).then([port]() -> future<> {
            std::cout << "Seastar HTTP server listening on port " << port << " ...\n";
            return sleep_abortable(std::chrono::hours(24)); 
        });
    });
}
