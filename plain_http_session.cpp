#include "plain_http_session.h"

plain_http_session::plain_http_session(beast::tcp_stream&& stream, beast::flat_buffer&& buffer)
	: http_session<plain_http_session>(
		std::move(buffer)
		)
	, stream_(std::move(stream))
{

}

void plain_http_session::run()
{
	this->do_read();
}

beast::tcp_stream& plain_http_session::stream()
{
	return stream_;
}

beast::tcp_stream plain_http_session::release_stream()
{
	return std::move(stream_);
}

void plain_http_session::do_eof()
{
	// Send a TCP shutdown
	beast::error_code ec;
	stream_.socket().shutdown(tcp::socket::shutdown_send, ec);

	// At this point the connection is closed gracefully
}

