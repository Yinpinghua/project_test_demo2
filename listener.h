#ifndef listener_h__
#define listener_h__

#include "detect_session.h"

// Accepts incoming connections and launches the sessions
class listener : public std::enable_shared_from_this<listener>
{
public:
	listener(
		net::io_context& ioc,
		ssl::context& ctx,
		tcp::endpoint endpoint);

	// Start accepting incoming connections
	void
		run();

private:
	void
		do_accept();
	void
		on_accept(beast::error_code ec, tcp::socket socket);
private:
	net::io_context& ioc_;
	ssl::context& ctx_;
	tcp::acceptor acceptor_;
};

#endif // listener_h__
