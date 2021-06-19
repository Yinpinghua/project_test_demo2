#include "plain_websocket_session.h"

plain_websocket_session::plain_websocket_session(beast::tcp_stream&& stream)
	: ws_(std::move(stream))
{

}

websocket::stream<beast::tcp_stream>& plain_websocket_session::ws()
{
	return ws_;
}
