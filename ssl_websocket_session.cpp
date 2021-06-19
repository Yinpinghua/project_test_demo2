#include "ssl_websocket_session.h"

ssl_websocket_session::ssl_websocket_session(beast::ssl_stream<beast::tcp_stream>&& stream)
	: ws_(std::move(stream))
{
}

websocket::stream<
	beast::ssl_stream<beast::tcp_stream>>&ssl_websocket_session::ws()
{
	return ws_;
}

