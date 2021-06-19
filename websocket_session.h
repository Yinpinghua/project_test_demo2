#ifndef websocket_session_h__
#define websocket_session_h__

#include "common.h"

// Echoes back all received WebSocket messages.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derived>
class websocket_session
{
public:
	websocket_session() = default;
	virtual ~websocket_session() = default;
	// Start the asynchronous operation
	template<class Body, class Allocator>
	void
		run(http::request<Body, http::basic_fields<Allocator>> req)
	{
		// Accept the WebSocket upgrade request
		do_accept(std::move(req));
	}
private:
	// Access the derived class, this is part of
	// the Curiously Recurring Template Pattern idiom.
	Derived&
		derived()
	{
		return static_cast<Derived&>(*this);
	}

	// Start the asynchronous operation
	template<class Body, class Allocator>
	void
		do_accept(http::request<Body, http::basic_fields<Allocator>> req)
	{
		// Set suggested timeout settings for the websocket
		derived().ws().set_option(
			websocket::stream_base::timeout::suggested(
				beast::role_type::server));

		// Set a decorator to change the Server of the handshake
		derived().ws().set_option(
			websocket::stream_base::decorator(
				[](websocket::response_type& res)
				{
					res.set(http::field::server,
						std::string(BOOST_BEAST_VERSION_STRING) +
						" advanced-server-flex");
				}));

		// Accept the websocket handshake
		derived().ws().async_accept(
			req,
			beast::bind_front_handler(
				&websocket_session::on_accept,
				derived().shared_from_this()));
	}

	void
		on_accept(beast::error_code ec)
	{
		if (ec)
			return fail(ec, "accept");

		// Read a message
		do_read();
	}

	void
		do_read()
	{
		// Read a message into our buffer
		derived().ws().async_read(
			buffer_,
			beast::bind_front_handler(
				&websocket_session::on_read,
				derived().shared_from_this()));
	}

	void
		on_read(
			beast::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		// This indicates that the websocket_session was closed
		if (ec == websocket::error::closed)
			return;

		if (ec)
			return fail(ec, "read");

		// Echo the message
		derived().ws().text(derived().ws().got_text());
		derived().ws().async_write(
			buffer_.data(),
			beast::bind_front_handler(
				&websocket_session::on_write,
				derived().shared_from_this()));
	}
	void
		on_write(
			beast::error_code ec,
			std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		// Clear the buffer
		buffer_.consume(buffer_.size());

		// Do another read
		do_read();
	}
	private:
		beast::flat_buffer buffer_;
};
#endif // websocket_session_h__
