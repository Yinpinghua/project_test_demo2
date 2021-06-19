#ifndef plain_websocket_session_h__
#define plain_websocket_session_h__
#include "websocket_session.h"

// Handles a plain WebSocket connection
class plain_websocket_session
	: public websocket_session<plain_websocket_session>
	, public std::enable_shared_from_this<plain_websocket_session>
{
	websocket::stream<beast::tcp_stream> ws_;

public:
	// Create the session
	explicit
		plain_websocket_session(
			beast::tcp_stream&& stream);

	~plain_websocket_session() = default;
	// Called by the base class
	websocket::stream<beast::tcp_stream>&
		ws();
};
#endif // plain_websocket_session_h__
