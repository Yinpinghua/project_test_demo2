#ifndef http_session_h__
#define http_session_h__

#include "plain_websocket_session.h"
#include "ssl_websocket_session.h"

// Handles an HTTP server connection.
// This uses the Curiously Recurring Template Pattern so that
// the same code works with both SSL streams and regular sockets.
template<class Derive>
class http_session
{
public:
	// Construct the session
	explicit http_session(
		beast::flat_buffer buffer)
		:buffer_(std::move(buffer))
	{

	}

	void set_io_servrer(const net::executor& io)
	{
		//The SSL context is required, and holds certificates
		ssl::context ctx(ssl::context::sslv23_client);
		csstream_ = std::make_shared<beast::ssl_stream<beast::tcp_stream>>(io, ctx);
		client_socket_attribute(csstream_);
	}

	virtual ~http_session() = default;
protected:
	void do_read() {
		// Construct a new parser for each message
		parser_.emplace();

		// Apply a reasonable limit to the allowed size
		// of the body in bytes to prevent abuse.
		parser_->body_limit(10000);

		// Set the timeout.
		beast::get_lowest_layer(
			derived().stream()).expires_after(std::chrono::seconds(30));

		// Read a request using the parser-oriented interface
		http::async_read(
			derived().stream(),
			buffer_,
			*parser_,
			beast::bind_front_handler(
				&http_session::on_read,
				derived().shared_from_this()));
	}
private:
	// Access the derived class, this is part of
// the Curiously Recurring Template Pattern idiom.
	Derive& derived()
	{
		return static_cast<Derive&>(*this);
	}

	template<class Body, class Allocator>
	void
		make_websocket_session(
			beast::tcp_stream stream,
			http::request<Body, http::basic_fields<Allocator>> req) {
		std::make_shared<plain_websocket_session>(
			std::move(stream))->run(std::move(req));
	}

	template<class Body, class Allocator>
	void
		make_websocket_session(
			beast::ssl_stream<beast::tcp_stream> stream,
			http::request<Body, http::basic_fields<Allocator>> req) {
		std::make_shared<ssl_websocket_session>(
			std::move(stream))->run(std::move(req));
	}
	void
		on_read(beast::error_code ec, std::size_t bytes_transferred) {
		boost::ignore_unused(bytes_transferred);

		// This means they closed the connection
		if (ec == http::error::end_of_stream)
			return derived().do_eof();

		if (ec)
			return fail(ec, "read");

		// See if it is a WebSocket Upgrade
		if (websocket::is_upgrade(parser_->get()))
		{
			// Disable the timeout.
			// The websocket::stream uses its own timeout settings.
			beast::get_lowest_layer(derived().stream()).expires_never();

			// Create a websocket session, transferring ownership
			// of both the socket and the HTTP request.
			return make_websocket_session(
				derived().release_stream(),
				parser_->release());
		}

		// Send the response
		client_send_msg(parser_->release());
	}

	void
		on_write(bool close, beast::error_code ec, std::size_t bytes_transferred)
	{
		boost::ignore_unused(bytes_transferred);

		if (ec)
			return fail(ec, "write");

		if (close)
		{
			// This means we should close the connection, usually because
			// the response indicated the "Connection: close" semantic.
			return derived().do_eof();
		}

		do_read();
	}
	template<
		class Body, class Allocator>
		void
		handle_request(
			http::request<Body, http::basic_fields<Allocator>>&& req)
	{
		std::string body = "hello";

		// Respond to GET request
		http::response<http::string_body> res{
			std::piecewise_construct,
			std::make_tuple(std::move(body)),
			std::make_tuple(http::status::ok, req.version()) };
		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
		res.set(http::field::content_type, "text/plain");
		res.content_length(body.size());
		res.keep_alive(req.keep_alive());
		res.prepare_payload();
		return write(std::move(res));
	}

	void write(http::response<http::string_body>&& res)
	{
		msg_ = std::move(res);

		http::async_write(
			derived().stream(),
			msg_,
			beast::bind_front_handler(
				&http_session::on_write,
				derived().shared_from_this(),
				msg_.need_eof()));
	}

	template<class Stream_type>
	void client_socket_attribute(Stream_type& stream)
	{
		beast::error_code ec;
		beast::get_lowest_layer(*stream).socket().open(boost::asio::ip::tcp::v4(), ec);
		beast::get_lowest_layer(*stream).socket().set_option(boost::asio::ip::tcp::no_delay(true), ec);
		beast::get_lowest_layer(*stream).socket().set_option(boost::asio::socket_base::linger(true, 0), ec);
		beast::get_lowest_layer(*stream).socket().set_option(boost::asio::socket_base::reuse_address(true), ec);
	}

	void client_send_msg(http::request<http::string_body>&& msg)
	{
		client_send_msg_ = std::move(msg);

		if (!is_connect_) {
			client_run();
			return;
		}

		client_send_write_https_msg();
	}

	void client_run()
	{
		std::string SourceAddress = "125.124.255.161";
		std::uint16_t port = 443;
		client_connect(std::move(SourceAddress), port);
	}

	void client_connect(std::string&& source_host, std::uint16_t port)
	{
		// Set the timeout.
		beast::get_lowest_layer(*csstream_).expires_after(std::chrono::seconds(30));
		auto result = net::ip::tcp::endpoint(net::ip::address::from_string(source_host),port);
		beast::get_lowest_layer(*csstream_).async_connect(
			result, beast::bind_front_handler(
				&http_session::client_on_connect,
				derived().shared_from_this()));
	}

	void client_on_connect(const beast::error_code& ec) 
	{
		beast::get_lowest_layer(*csstream_).expires_never();

		beast::get_lowest_layer(*csstream_).expires_after(std::chrono::seconds(30));
		csstream_->async_handshake(ssl::stream_base::client, client_buffer_.data(),
			boost::beast::bind_front_handler(
				[self =derived().shared_from_this()](const beast::error_code& ec, std::size_t bytes_used) {
					beast::get_lowest_layer(*self->csstream_).expires_never();
					if (ec) {
						return;
					}

					self->client_buffer_.consume(bytes_used);
					self->client_send_write_https_msg();
				}));
	}

	void client_send_write_https_msg()
	{
		if (csstream_ == nullptr) {
			return;
		}

		http::async_write(*csstream_,client_send_msg_,
			boost::beast::bind_front_handler(
				[self = derived().shared_from_this()](const beast::error_code& ec, std::size_t bytes_transferred){
			if (ec) 
			{
				return;
			}
			
			self->client_read_https_msg();
		}));
	}

	void client_read_https_msg()
	{
		client_read_parser_.emplace();

		http::async_read(*csstream_,
			client_buffer_,
			*client_read_parser_,
			boost::beast::bind_front_handler(
				[self = derived().shared_from_this()](const beast::error_code& ec, std::size_t bytes_transferred){
			if (ec)
			{
				return;
			}

			self->server_send_msg(self->client_read_parser_->release());
		}));
	}

	void server_send_msg(http::response<http::string_body>&& msg)
	{
		msg = std::move(msg);

		http::async_write(derived().stream(), msg_,
			boost::beast::bind_front_handler(
				[self = derived().shared_from_this()](const beast::error_code& ec, std::size_t bytes_transferred){
			if (ec)
			{
				return;
			}

			self->do_read();
		}));
	}
protected:
	beast::flat_buffer buffer_;
private:
	bool is_connect_=false;
	http::response<http::string_body> msg_;
	http::request<http::string_body> client_send_msg_;
	beast::flat_buffer client_buffer_;
	// The parser is stored in an optional container so we can
	// construct it from scratch it at the beginning of each new message.
	boost::optional<http::request_parser<http::string_body>> parser_;
	boost::optional<http::response_parser<http::string_body>> client_read_parser_;
	std::shared_ptr<beast::ssl_stream<beast::tcp_stream>>csstream_{};//client
};

#endif // http_session_h__
