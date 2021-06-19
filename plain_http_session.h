#ifndef plain_http_session_h__
#define plain_http_session_h__

#include "http_session.hpp"
// Handles a plain HTTP connection
class plain_http_session
	: public http_session<plain_http_session>
	, public std::enable_shared_from_this<plain_http_session>
{
public:
	// Create the session
	plain_http_session(
		beast::tcp_stream&& stream,
		beast::flat_buffer&& buffer);

	~plain_http_session() = default;
	// Start the session
	void
		run();

	// Called by the base class
	beast::tcp_stream&
		stream();
	// Called by the base class
	beast::tcp_stream
		release_stream();
	// Called by the base class
	void
		do_eof();
private:
	beast::tcp_stream stream_;
};

#endif // plain_http_session_h__
