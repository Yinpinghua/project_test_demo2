#ifndef detect_session_h__
#define detect_session_h__
#include "common.h"

// Detects SSL handshakes
class detect_session : public std::enable_shared_from_this<detect_session>
{
public:
	detect_session(
			tcp::socket&& socket,
			ssl::context& ctx);

	// Launch the detector
	void run();
private:
	void on_run();
	void on_detect(beast::error_code ec, bool result);
private:
	beast::tcp_stream stream_;
	ssl::context& ctx_;
	beast::flat_buffer buffer_;
};

#endif // detect_session_h__
