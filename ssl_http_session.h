#ifndef ssl_http_session_h__
#define ssl_http_session_h__
#include "http_session.hpp"

// Handles an SSL HTTP connection
class ssl_http_session
	: public http_session<ssl_http_session>
	, public std::enable_shared_from_this<ssl_http_session>
{
public:
	// Create the http_session
	ssl_http_session(
		beast::tcp_stream&& stream,
		ssl::context& ctx,
		beast::flat_buffer&& buffer);

	~ssl_http_session() = default;
	// Start the session
	void
		run();
	// Called by the base class
	beast::ssl_stream<beast::tcp_stream>&
		stream();
	// Called by the base class
	beast::ssl_stream<beast::tcp_stream>
		release_stream();
	// Called by the base class
	void
		do_eof();
private:
	void
		on_handshake(
			beast::error_code ec,
			std::size_t bytes_used);
	void
		on_shutdown(beast::error_code ec);
private:
	beast::ssl_stream<beast::tcp_stream> stream_;

};

#endif // ssl_http_session_h__
