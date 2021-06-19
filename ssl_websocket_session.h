#ifndef ssl_websocket_session_h__
#define ssl_websocket_session_h__

#include "websocket_session.h"

// Handles an SSL WebSocket connection
class ssl_websocket_session
	: public websocket_session<ssl_websocket_session>
	, public std::enable_shared_from_this<ssl_websocket_session>
{
public:
	// Create the ssl_websocket_session
	explicit
		ssl_websocket_session(
			beast::ssl_stream<beast::tcp_stream>&& stream);

	~ssl_websocket_session() = default;
	// Called by the base class
	websocket::stream<
		beast::ssl_stream<beast::tcp_stream>>&
		ws();
private:
	websocket::stream<
		beast::ssl_stream<beast::tcp_stream>> ws_;
};
#endif // ssl_websocket_session_h__
