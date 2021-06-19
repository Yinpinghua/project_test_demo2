////
////#include <boost/beast/core.hpp>
////#include <boost/beast/http.hpp>
////#include <boost/beast/ssl.hpp>
////#include <boost/beast/version.hpp>
////#include <boost/asio/dispatch.hpp>
////#include <boost/asio/strand.hpp>
////#include <boost/config.hpp>
////#include <boost/filesystem.hpp>
////#include <algorithm>
////#include <cstdlib>
////#include <functional>
////#include <iostream>
////#include <memory>
////#include <string>
////#include <thread>
////
////struct ssl_configure {
////	std::string cert_file;          //private cert
////	std::string key_file;           //private key
////	std::string passp_hrase;        //password;//私有key，是否输入密码
////	std::string pem_flie;           //*.pem文件
////};
////
////namespace beast = boost::beast;         // from <boost/beast.hpp>
////namespace http = beast::http;           // from <boost/beast/http.hpp>
////namespace net = boost::asio;            // from <boost/asio.hpp>
////namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
////using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
////
////
////// This function produces an HTTP response for the given
////// request. The type of the response object depends on the
////// contents of the request, so the interface requires the
////// caller to pass a generic lambda for receiving the response.
////template<
////	class Body, class Allocator,
////	class Send>
////	void
////	handle_request(
////		beast::string_view doc_root,
////		http::request<Body, http::basic_fields<Allocator>>&& req,
////		Send&& send)
////{
////	std::string data = "hello world";
////
////
////	int len = data.size();
////	http::response<http::string_body>res{
////		std::piecewise_construct,
////		std::make_tuple(std::move(data)),
////		std::make_tuple(http::status::ok, req.version()) };
////	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
////	//res.set(http::field::content_type, mime_type(path));
////	res.content_length(len);
////
////	return send(std::move(res));
////}
////
//////------------------------------------------------------------------------------
////
////// Report a failure
////void
////fail(beast::error_code ec, char const* what)
////{
////	// ssl::error::stream_truncated, also known as an SSL "short read",
////	// indicates the peer closed the connection without performing the
////	// required closing handshake (for example, Google does this to
////	// improve performance). Generally this can be a security issue,
////	// but if your communication protocol is self-terminated (as
////	// it is with both HTTP and WebSocket) then you may simply
////	// ignore the lack of close_notify.
////	//
////	// https://github.com/boostorg/beast/issues/38
////	//
////	// https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
////	//
////	// When a short read would cut off the end of an HTTP message,
////	// Beast returns the error beast::http::error::partial_message.
////	// Therefore, if we see a short read here, it has occurred
////	// after the message has been completed, so it is safe to ignore it.
////
////	if (ec == net::ssl::error::stream_truncated)
////		return;
////
////	std::cerr << what << ": " << ec.message() << "\n";
////}
////
////// Handles an HTTP server connection.
////// This uses the Curiously Recurring Template Pattern so that
////// the same code works with both SSL streams and regular sockets.
////template<class Derived>
////class session
////{
////	// Access the derived class, this is part of
////	// the Curiously Recurring Template Pattern idiom.
////	Derived&
////		derived()
////	{
////		return static_cast<Derived&>(*this);
////	}
////
////	// This is the C++11 equivalent of a generic lambda.
////	// The function object is used to send an HTTP message.
////	struct send_lambda
////	{
////		session& self_;
////
////		explicit
////			send_lambda(session& self)
////			: self_(self)
////		{
////		}
////
////		template<bool isRequest, class Body, class Fields>
////		void
////			operator()(http::message<isRequest, Body, Fields>&& msg) const
////		{
////			// The lifetime of the message has to extend
////			// for the duration of the async operation so
////			// we use a shared_ptr to manage it.
////			auto sp = std::make_shared<
////				http::message<isRequest, Body, Fields>>(std::move(msg));
////
////			// Store a type-erased version of the shared
////			// pointer in the class to keep it alive.
////			self_.res_ = sp;
////
////			// Write the response
////			http::async_write(
////				self_.derived().stream(),
////				*sp,
////				beast::bind_front_handler(
////					&session::on_write,
////					self_.derived().shared_from_this(),
////					sp->need_eof()));
////		}
////	};
////
////	std::shared_ptr<std::string const> doc_root_;
////	http::request<http::string_body> req_;
////	std::shared_ptr<void> res_;
////	send_lambda lambda_;
////
////protected:
////	beast::flat_buffer buffer_;
////
////public:
////	// Take ownership of the buffer
////	session(
////		beast::flat_buffer buffer,
////		std::shared_ptr<std::string const> const& doc_root)
////		: doc_root_(doc_root)
////		, lambda_(*this)
////		, buffer_(std::move(buffer))
////	{
////	}
////
////	~session() {
////		std::cout << "~session" << std::endl;
////	}
////
////	void
////		do_read()
////	{
////		// Set the timeout.
////		beast::get_lowest_layer(
////			derived().stream()).expires_after(std::chrono::seconds(30));
////
////		// Read a request
////		http::async_read(
////			derived().stream(),
////			buffer_,
////			req_,
////			beast::bind_front_handler(
////				&session::on_read,
////				derived().shared_from_this()));
////	}
////
////	void
////		on_read(
////			beast::error_code ec,
////			std::size_t bytes_transferred)
////	{
////		boost::ignore_unused(bytes_transferred);
////
////		// This means they closed the connection
////		if (ec == http::error::end_of_stream)
////			return derived().do_eof();
////
////		if (ec)
////			return fail(ec, "read");
////
////		// Send the response
////		handle_request(*doc_root_, std::move(req_), lambda_);
////	}
////
////	void
////		on_write(
////			bool close,
////			beast::error_code ec,
////			std::size_t bytes_transferred)
////	{
////		boost::ignore_unused(bytes_transferred);
////
////		if (ec)
////			return fail(ec, "write");
////
////		if (close)
////		{
////			// This means we should close the connection, usually because
////			// the response indicated the "Connection: close" semantic.
////			return derived().do_eof();
////		}
////
////		// We're done with the response so delete it
////		res_ = nullptr;
////
////		// Read another request
////		do_read();
////	}
////};
////
////// Handles a plain HTTP connection
////class plain_session
////	: public session<plain_session>
////	, public std::enable_shared_from_this<plain_session>
////{
////	beast::tcp_stream stream_;
////
////public:
////	// Create the session
////	plain_session(
////		tcp::socket&& socket,
////		beast::flat_buffer buffer,
////		std::shared_ptr<std::string const> const& doc_root)
////		: session<plain_session>(
////			std::move(buffer),
////			doc_root)
////		, stream_(std::move(socket))
////	{
////	}
////
////	// Called by the base class
////	beast::tcp_stream&
////		stream()
////	{
////		return stream_;
////	}
////
////	// Start the asynchronous operation
////	void
////		run()
////	{
////		// We need to be executing within a strand to perform async operations
////		// on the I/O objects in this session. Although not strictly necessary
////		// for single-threaded contexts, this example code is written to be
////		// thread-safe by default.
////		net::dispatch(stream_.get_executor(),
////			beast::bind_front_handler(
////				&session::do_read,
////				shared_from_this()));
////	}
////
////	void
////		do_eof()
////	{
////		// Send a TCP shutdown
////		beast::error_code ec;
////		stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
////
////		// At this point the connection is closed gracefully
////	}
////};
////
////// Handles an SSL HTTP connection
////class ssl_session
////	: public session<ssl_session>
////	, public std::enable_shared_from_this<ssl_session>
////{
////	beast::ssl_stream<beast::tcp_stream> stream_;
////
////public:
////	// Create the session
////	ssl_session(
////		tcp::socket&& socket,
////		ssl::context& ctx,
////		beast::flat_buffer buffer,
////		std::shared_ptr<std::string const> const& doc_root)
////		: session<ssl_session>(
////			std::move(buffer),
////			doc_root)
////		, stream_(std::move(socket), ctx)
////	{
////	}
////
////	// Called by the base class
////	beast::ssl_stream<beast::tcp_stream>&
////		stream()
////	{
////		return stream_;
////	}
////
////	// Start the asynchronous operation
////	void
////		run()
////	{
////		auto self = shared_from_this();
////		// We need to be executing within a strand to perform async operations
////		// on the I/O objects in this session.
////		net::dispatch(stream_.get_executor(), [self]() {
////			// Set the timeout.
////			beast::get_lowest_layer(self->stream_).expires_after(
////				std::chrono::seconds(1));
////
////			// Perform the SSL handshake
////			// Note, this is the buffered version of the handshake.
////			self->stream_.async_handshake(
////				ssl::stream_base::server,
////				self->buffer_.data(),
////				beast::bind_front_handler(
////					&ssl_session::on_handshake,
////					self));
////			});
////	}
////
////	void
////		on_handshake(
////			beast::error_code ec,
////			std::size_t bytes_used)
////	{
////		if (ec)
////			return fail(ec, "handshake");
////
////		beast::get_lowest_layer(stream_).expires_never();
////		// Consume the portion of the buffer used by the handshake
////		buffer_.consume(bytes_used);
////
////		do_read();
////	}
////
////	void
////		do_eof()
////	{
////		// Set the timeout.
////		beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
////
////		// Perform the SSL shutdown
////		stream_.async_shutdown(
////			beast::bind_front_handler(
////				&ssl_session::on_shutdown,
////				shared_from_this()));
////	}
////
////	void
////		on_shutdown(beast::error_code ec)
////	{
////		if (ec)
////			return fail(ec, "shutdown");
////
////		// At this point the connection is closed gracefully
////	}
////};
////
//////------------------------------------------------------------------------------
////
////// Detects SSL handshakes
////class detect_session : public std::enable_shared_from_this<detect_session>
////{
////	beast::tcp_stream stream_;
////	ssl::context& ctx_;
////	std::shared_ptr<std::string const> doc_root_;
////	beast::flat_buffer buffer_;
////
////public:
////	detect_session(
////		tcp::socket&& socket,
////		ssl::context& ctx,
////		std::shared_ptr<std::string const> const& doc_root)
////		: stream_(std::move(socket))
////		, ctx_(ctx)
////		, doc_root_(doc_root)
////	{
////	}
////
////	~detect_session() {
////		int i = 100;
////	}
////
////	// Launch the detector
////	void
////		run()
////	{
////		// Set the timeout.
////		beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
////
////		// Detect a TLS handshake
////		async_detect_ssl(
////			stream_,
////			buffer_,
////			beast::bind_front_handler(
////				&detect_session::on_detect,
////				shared_from_this()));
////	}
////
////	void
////		on_detect(beast::error_code ec, bool result)
////	{
////		if (ec)
////			return fail(ec, "detect");
////
////		if (result)
////		{
////			// Launch SSL session
////			std::make_shared<ssl_session>(
////				stream_.release_socket(),
////				ctx_,
////				std::move(buffer_),
////				doc_root_)->run();
////			return;
////		}
////
////		// Launch plain session
////		std::make_shared<plain_session>(
////			stream_.release_socket(),
////			std::move(buffer_),
////			doc_root_)->run();
////	}
////};
////
////// Accepts incoming connections and launches the sessions
////class listener : public std::enable_shared_from_this<listener>
////{
////	net::io_context& ioc_;
////	ssl::context& ctx_;
////	tcp::acceptor acceptor_;
////	std::shared_ptr<std::string const> doc_root_;
////
////public:
////	listener(
////		net::io_context& ioc,
////		ssl::context& ctx,
////		tcp::endpoint endpoint,
////		std::shared_ptr<std::string const> const& doc_root)
////		: ioc_(ioc)
////		, ctx_(ctx)
////		, acceptor_(net::make_strand(ioc))
////		, doc_root_(doc_root)
////	{
////		beast::error_code ec;
////
////		// Open the acceptor
////		acceptor_.open(endpoint.protocol(), ec);
////		if (ec)
////		{
////			fail(ec, "open");
////			return;
////		}
////
////		// Allow address reuse
////		acceptor_.set_option(net::socket_base::reuse_address(true), ec);
////		if (ec)
////		{
////			fail(ec, "set_option");
////			return;
////		}
////
////		// Bind to the server address
////		acceptor_.bind(endpoint, ec);
////		if (ec)
////		{
////			fail(ec, "bind");
////			return;
////		}
////
////		// Start listening for connections
////		acceptor_.listen(
////			net::socket_base::max_listen_connections, ec);
////		if (ec)
////		{
////			fail(ec, "listen");
////			return;
////		}
////	}
////
////	// Start accepting incoming connections
////	void
////		run()
////	{
////		do_accept();
////	}
////
////private:
////	void
////		do_accept()
////	{
////		// The new connection gets its own strand
////		acceptor_.async_accept(
////			net::make_strand(ioc_),
////			beast::bind_front_handler(
////				&listener::on_accept,
////				shared_from_this()));
////	}
////
////	void
////		on_accept(beast::error_code ec, tcp::socket socket)
////	{
////		if (ec)
////		{
////			fail(ec, "accept");
////		}
////		else
////		{
////			boost::system::error_code ec;
////			//关闭牛逼的算法(nagle算法),防止TCP的数据包在饱满时才发送过去
////			boost::asio::ip::tcp::no_delay option(true);
////			//快速关闭,提高高并发,缓冲区存留的数据直接丢弃 
////			boost::asio::socket_base::linger linger_option(true, 0);
////			boost::asio::socket_base::reuse_address readdress(true);
////
////			socket.set_option(linger_option, ec);
////			socket.set_option(option, ec);
////
////			socket.set_option(readdress, ec);
////
////			// Create the detector session and run it
////			std::make_shared<detect_session>(
////				std::move(socket),
////				ctx_,
////				doc_root_)->run();
////		}
////
////		// Accept another connection
////		do_accept();
////	}
////};
////
//////------------------------------------------------------------------------------
////
////int main(int argc, char* argv[])
////{
////	namespace fs = boost::filesystem;
////
////	auto const address = net::ip::make_address("0.0.0.0");
////	auto const port = 8443;
////	auto const doc_root = std::make_shared<std::string>(".");
////	int threads = std::thread::hardware_concurrency();
////
////	// The io_context is required for all I/O
////	net::io_context ioc{ threads };
////
////	unsigned long ssl_options = boost::asio::ssl::context::default_workarounds
////		| boost::asio::ssl::context::no_sslv3
////		| boost::asio::ssl::context::no_sslv2
////		| boost::asio::ssl::context::single_dh_use;
////	// The SSL context is required, and holds certificates
////	ssl::context ctx{ ssl::context::tlsv12 };
////
////	ssl_configure ssl_conf{ "./crt.crt","./key.key" };
////
////	//boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv13);//tsl1.3
////	//boost::asio::ssl::context ssl_context(boost::asio::ssl::context::sslv23);
////	ctx.set_options(ssl_options);
////
////	if (!ssl_conf.passp_hrase.empty()) {
////		ctx.set_password_callback([ssl_conf](size_t, boost::asio::ssl::context_base::password_purpose) {return ssl_conf.passp_hrase; });
////	}
////
////	boost::system::error_code ec;
////	if (fs::exists(ssl_conf.cert_file, ec)) {
////		ctx.use_certificate_chain_file(std::move(ssl_conf.cert_file));
////	}
////	else {
////		std::cout << "server.crt is empty" << std::endl;
////		return false;
////	}
////
////	if (fs::exists(ssl_conf.key_file, ec)) {
////		ctx.use_private_key_file(std::move(ssl_conf.key_file), boost::asio::ssl::context::pem);
////	}
////	else {
////		std::cout << "server.key is empty" << std::endl;
////		return false;
////	}
////
////	if (fs::exists(ssl_conf.pem_flie, ec)) {
////		ctx.use_tmp_dh_file(std::move(ssl_conf.pem_flie));
////	}
////
////
////	// Create and launch a listening port
////	std::make_shared<listener>(
////		ioc,
////		ctx,
////		tcp::endpoint{ address, port },
////		doc_root)->run();
////
////	// Run the I/O service on the requested number of threads
////	std::vector<std::thread> v;
////	v.reserve(threads - 1);
////	for (auto i = threads - 1; i > 0; --i)
////		v.emplace_back(
////			[&ioc]
////			{
////				ioc.run();
////			});
////	ioc.run();
////
////	return EXIT_SUCCESS;
////}
////
//////
////// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
//////
////// Distributed under the Boost Software License, Version 1.0. (See accompanying
////// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//////
////// Official repository: https://github.com/boostorg/beast
//////
////
//////------------------------------------------------------------------------------
//////
////// Example: WebSocket SSL client, asynchronous
//////
//////------------------------------------------------------------------------------
////
////#include "example/common/root_certificates.hpp"
//
////#include <boost/beast/core.hpp>
////#include <boost/beast/ssl.hpp>
////#include <boost/beast/websocket.hpp>
////#include <boost/beast/websocket/ssl.hpp>
////#include <boost/asio/strand.hpp>
////#include <cstdlib>
////#include <functional>
////#include <iostream>
////#include <memory>
////#include <string>
////
////namespace beast = boost::beast;         // from <boost/beast.hpp>
////namespace http = beast::http;           // from <boost/beast/http.hpp>
////namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
////namespace net = boost::asio;            // from <boost/asio.hpp>
////namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
////using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
////
//////------------------------------------------------------------------------------
////
////// Report a failure
////void
////fail(beast::error_code ec, char const* what)
////{
////    std::cerr << what << ": " << ec.message() << "\n";
////}
////
////// Sends a WebSocket message and prints the response
////class session : public std::enable_shared_from_this<session>
////{
////    tcp::resolver resolver_;
////    websocket::stream<
////        beast::ssl_stream<beast::tcp_stream>> ws_;
////    beast::flat_buffer buffer_;
////    std::string host_;
////    std::string text_;
////
////public:
////    // Resolver and socket require an io_context
////    explicit
////        session(net::io_context& ioc, ssl::context& ctx)
////        : resolver_(net::make_strand(ioc))
////        , ws_(net::make_strand(ioc), ctx)
////    {
////    }
////
////    // Start the asynchronous operation
////    void
////        run(
////            char const* host,
////            char const* port,
////            char const* text)
////    {
////        // Save these for later
////        host_ = host;
////        text_ = text;
////
////        // Look up the domain name
////        resolver_.async_resolve(
////            host,
////            port,
////            beast::bind_front_handler(
////                &session::on_resolve,
////                shared_from_this()));
////    }
////
////    void
////        on_resolve(
////            beast::error_code ec,
////            tcp::resolver::results_type results)
////    {
////        if (ec)
////            return fail(ec, "resolve");
////
////        // Set a timeout on the operation
////        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
////
////        // Make the connection on the IP address we get from a lookup
////        beast::get_lowest_layer(ws_).async_connect(
////            results,
////            beast::bind_front_handler(
////                &session::on_connect,
////                shared_from_this()));
////    }
////
////    void
////        on_connect(beast::error_code ec, tcp::resolver::results_type::endpoint_type ep)
////    {
////        if (ec)
////            return fail(ec, "connect");
////
////        // Update the host_ string. This will provide the value of the
////        // Host HTTP header during the WebSocket handshake.
////        // See https://tools.ietf.org/html/rfc7230#section-5.4
////        host_ += ':' + std::to_string(ep.port());
////
////        // Set a timeout on the operation
////        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));
////
////        // Perform the SSL handshake
////        ws_.next_layer().async_handshake(
////            ssl::stream_base::client,
////            beast::bind_front_handler(
////                &session::on_ssl_handshake,
////                shared_from_this()));
////    }
////
////    void
////        on_ssl_handshake(beast::error_code ec)
////    {
////        if (ec)
////            return fail(ec, "ssl_handshake");
////
////        // Turn off the timeout on the tcp_stream, because
////        // the websocket stream has its own timeout system.
////        beast::get_lowest_layer(ws_).expires_never();
////
////        // Set suggested timeout settings for the websocket
////        ws_.set_option(
////            websocket::stream_base::timeout::suggested(
////                beast::role_type::client));
////
////        // Set a decorator to change the User-Agent of the handshake
////        ws_.set_option(websocket::stream_base::decorator(
////            [](websocket::request_type& req)
////            {
////                req.set(http::field::user_agent,
////                    std::string(BOOST_BEAST_VERSION_STRING) +
////                    " websocket-client-async-ssl");
////            }));
////
////        // Perform the websocket handshake
////        ws_.async_handshake(host_, "/",
////            beast::bind_front_handler(
////                &session::on_handshake,
////                shared_from_this()));
////    }
////
////    void
////        on_handshake(beast::error_code ec)
////    {
////        if (ec)
////            return fail(ec, "handshake");
////
////        // Send the message
////        ws_.async_write(
////            net::buffer(text_),
////            beast::bind_front_handler(
////                &session::on_write,
////                shared_from_this()));
////    }
////
////    void
////        on_write(
////            beast::error_code ec,
////            std::size_t bytes_transferred)
////    {
////        boost::ignore_unused(bytes_transferred);
////
////        if (ec)
////            return fail(ec, "write");
////
////        // Read a message into our buffer
////        ws_.async_read(
////            buffer_,
////            beast::bind_front_handler(
////                &session::on_read,
////                shared_from_this()));
////    }
////
////    void
////        on_read(
////            beast::error_code ec,
////            std::size_t bytes_transferred)
////    {
////        boost::ignore_unused(bytes_transferred);
////
////        if (ec)
////            return fail(ec, "read");
////
////        // Close the WebSocket connection
////        ws_.async_close(websocket::close_code::normal,
////            beast::bind_front_handler(
////                &session::on_close,
////                shared_from_this()));
////    }
////
////    void
////        on_close(beast::error_code ec)
////    {
////        if (ec)
////            return fail(ec, "close");
////
////        // If we get here then the connection is closed gracefully
////
////        // The make_printable() function helps print a ConstBufferSequence
////        std::cout << beast::make_printable(buffer_.data()) << std::endl;
////    }
////};
////
//////------------------------------------------------------------------------------
////
////int main(int argc, char** argv)
////{
////    // Check command line arguments.
////    if (argc != 4)
////    {
////        std::cerr <<
////            "Usage: websocket-client-async-ssl <host> <port> <text>\n" <<
////            "Example:\n" <<
////            "    websocket-client-async-ssl echo.websocket.org 443 \"Hello, world!\"\n";
////        return EXIT_FAILURE;
////    }
////    auto const host = argv[1];
////    auto const port = argv[2];
////    auto const text = argv[3];
////
////    // The io_context is required for all I/O
////    net::io_context ioc;
////
////    // The SSL context is required, and holds certificates
////    ssl::context ctx{ ssl::context::tlsv12_client };
////
////    // This holds the root certificate used for verification
////    load_root_certificates(ctx);
////
////    // Launch the asynchronous operation
////    std::make_shared<session>(ioc, ctx)->run(host, port, text);
////
////    // Run the I/O service. The call will return when
////    // the socket is closed.
////    ioc.run();
////
////    return EXIT_SUCCESS;
////}
//
////#include "fields_alloc.hpp"
////#include <boost/beast/core.hpp>
////#include <boost/beast/http.hpp>
////#include <boost/beast/version.hpp>
////#include <boost/asio.hpp>
////#include <chrono>
////#include <cstdlib>
////#include <cstring>
////#include <iostream>
////#include <list>
////#include <memory>
////#include <string>
////
////namespace beast = boost::beast;         // from <boost/beast.hpp>
////namespace http = beast::http;           // from <boost/beast/http.hpp>
////namespace net = boost::asio;            // from <boost/asio.hpp>
////using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
////
////// Return a reasonable mime type based on the extension of a file.
////beast::string_view
////mime_type(beast::string_view path)
////{
////	using beast::iequals;
////	auto const ext = [&path]
////	{
////		auto const pos = path.rfind(".");
////		if (pos == beast::string_view::npos)
////			return beast::string_view{};
////		return path.substr(pos);
////	}();
////	if (iequals(ext, ".htm"))  return "text/html";
////	if (iequals(ext, ".html")) return "text/html";
////	if (iequals(ext, ".php"))  return "text/html";
////	if (iequals(ext, ".css"))  return "text/css";
////	if (iequals(ext, ".txt"))  return "text/plain";
////	if (iequals(ext, ".js"))   return "application/javascript";
////	if (iequals(ext, ".json")) return "application/json";
////	if (iequals(ext, ".xml"))  return "application/xml";
////	if (iequals(ext, ".swf"))  return "application/x-shockwave-flash";
////	if (iequals(ext, ".flv"))  return "video/x-flv";
////	if (iequals(ext, ".png"))  return "image/png";
////	if (iequals(ext, ".jpe"))  return "image/jpeg";
////	if (iequals(ext, ".jpeg")) return "image/jpeg";
////	if (iequals(ext, ".jpg"))  return "image/jpeg";
////	if (iequals(ext, ".gif"))  return "image/gif";
////	if (iequals(ext, ".bmp"))  return "image/bmp";
////	if (iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
////	if (iequals(ext, ".tiff")) return "image/tiff";
////	if (iequals(ext, ".tif"))  return "image/tiff";
////	if (iequals(ext, ".svg"))  return "image/svg+xml";
////	if (iequals(ext, ".svgz")) return "image/svg+xml";
////	return "application/text";
////}
////
////class http_worker
////{
////public:
////	http_worker(http_worker const&) = delete;
////	http_worker& operator=(http_worker const&) = delete;
////
////	http_worker(tcp::acceptor& acceptor, const std::string& doc_root) :
////		acceptor_(acceptor),
////		doc_root_(doc_root)
////	{
////	}
////
////	void start()
////	{
////		accept();
////		check_deadline();
////	}
////
////private:
////	using alloc_t = fields_alloc<char>;
////	//using request_body_t = http::basic_dynamic_body<beast::flat_static_buffer<1024 * 1024>>;
////	using request_body_t = http::string_body;
////
////	// The acceptor used to listen for incoming connections.
////	tcp::acceptor& acceptor_;
////
////	// The path to the root of the document directory.
////	std::string doc_root_;
////
////	// The socket for the currently connected client.
////	tcp::socket socket_{ acceptor_.get_executor() };
////
////	// The buffer for performing reads
////	beast::flat_static_buffer<8192> buffer_;
////
////	// The allocator used for the fields in the request and reply.
////	alloc_t alloc_{ 8192 };
////
////	// The parser for reading the requests
////	boost::optional<http::request_parser<request_body_t, alloc_t>> parser_;
////
////	// The timer putting a time limit on requests.
////	net::steady_timer request_deadline_{
////		acceptor_.get_executor(), (std::chrono::steady_clock::time_point::max)() };
////
////	// The string-based response message.
////	boost::optional<http::response<http::string_body, http::basic_fields<alloc_t>>> string_response_;
////
////	// The string-based response serializer.
////	boost::optional<http::response_serializer<http::string_body, http::basic_fields<alloc_t>>> string_serializer_;
////
////	// The file-based response message.
////	boost::optional<http::response<http::file_body, http::basic_fields<alloc_t>>> file_response_;
////
////	// The file-based response serializer.
////	boost::optional<http::response_serializer<http::file_body, http::basic_fields<alloc_t>>> file_serializer_;
////
////	void accept()
////	{
////		// Clean up any previous connection.
////		beast::error_code ec;
////		socket_.close(ec);
////		buffer_.consume(buffer_.size());
////
////		acceptor_.async_accept(
////			socket_,
////			[this](beast::error_code ec)
////			{
////				if (ec)
////				{
////					accept();
////				}
////				else
////				{
////					// Request must be fully processed within 60 seconds.
////					request_deadline_.expires_after(
////						std::chrono::seconds(60));
////
////					read_request();
////				}
////			});
////	}
////
////	void read_request()
////	{
////		// On each read the parser needs to be destroyed and
////		// recreated. We store it in a boost::optional to
////		// achieve that.
////		//
////		// Arguments passed to the parser constructor are
////		// forwarded to the message object. A single argument
////		// is forwarded to the body constructor.
////		//
////		// We construct the dynamic body with a 1MB limit
////		// to prevent vulnerability to buffer attacks.
////		//
////		parser_.emplace(
////			std::piecewise_construct,
////			std::make_tuple(),
////			std::make_tuple(alloc_));
////
////		http::async_read(
////			socket_,
////			buffer_,
////			*parser_,
////			[this](beast::error_code ec, std::size_t)
////			{
////				if (ec)
////					accept();
////				else
////					process_request(parser_->get());
////			});
////	}
////
////	void process_request(http::request<request_body_t, http::basic_fields<alloc_t>> const& req)
////	{
////		switch (req.method())
////		{
////		case http::verb::get:
////			send_file(req.target());
////			break;
////
////		default:
////			// We return responses indicating an error if
////			// we do not recognize the request method.
////			send_bad_response(
////				http::status::bad_request,
////				"Invalid request-method '" + std::string(req.method_string()) + "'\r\n");
////			break;
////		}
////	}
////
////	void send_bad_response(
////		http::status status,
////		std::string const& error)
////	{
////		string_response_.emplace(
////			std::piecewise_construct,
////			std::make_tuple(),
////			std::make_tuple(alloc_));
////
////		string_response_->result(status);
////		string_response_->keep_alive(false);
////		string_response_->set(http::field::server, "Beast");
////		string_response_->set(http::field::content_type, "text/plain");
////		string_response_->body() = error;
////		string_response_->prepare_payload();
////
////		string_serializer_.emplace(*string_response_);
////
////		http::async_write(
////			socket_,
////			*string_serializer_,
////			[this](beast::error_code ec, std::size_t)
////			{
////				socket_.shutdown(tcp::socket::shutdown_send, ec);
////				string_serializer_.reset();
////				string_response_.reset();
////				accept();
////			});
////	}
////
////	void send_file(beast::string_view target)
////	{
////		// Request path must be absolute and not contain "..".
////		if (target.empty() || target[0] != '/' || target.find("..") != std::string::npos)
////		{
////			send_bad_response(
////				http::status::not_found,
////				"File not found\r\n");
////			return;
////		}
////
////		std::string full_path = "11.txt";
////		//full_path.append(
////		//	target.data(),
////		//	target.size());
////
////		http::file_body::value_type file;
////		beast::error_code ec;
////		file.open(
////			full_path.c_str(),
////			beast::file_mode::read,
////			ec);
////		if (ec)
////		{
////			send_bad_response(
////				http::status::not_found,
////				"File not found\r\n");
////			return;
////		}
////
////		file_response_.emplace(
////			std::piecewise_construct,
////			std::make_tuple(),
////			std::make_tuple(alloc_));
////
////		file_response_->result(http::status::ok);
////		file_response_->keep_alive(false);
////		file_response_->set(http::field::server, "Beast");
////		file_response_->set(http::field::content_type, mime_type(std::string(target)));
////		file_response_->body() = std::move(file);
////		file_response_->prepare_payload();
////
////		file_serializer_.emplace(*file_response_);
////
////		http::async_write(
////			socket_,
////			*file_serializer_,
////			[this](beast::error_code ec, std::size_t)
////			{
////				socket_.shutdown(tcp::socket::shutdown_send, ec);
////				file_serializer_.reset();
////				file_response_.reset();
////				accept();
////			});
////	}
////
////	void check_deadline()
////	{
////		// The deadline may have moved, so check it has really passed.
////		if (request_deadline_.expiry() <= std::chrono::steady_clock::now())
////		{
////			// Close socket to cancel any outstanding operation.
////			beast::error_code ec;
////			socket_.close();
////
////			// Sleep indefinitely until we're given a new deadline.
////			request_deadline_.expires_at(
////				std::chrono::steady_clock::time_point::max());
////		}
////
////		request_deadline_.async_wait(
////			[this](beast::error_code)
////			{
////				check_deadline();
////			});
////	}
////};
////
////int main(int argc, char* argv[])
////{
////	try
////	{
////		auto const address = net::ip::make_address("0.0.0.0");
////		unsigned short port =9090;
////		std::string doc_root = "11.txt";
////		int num_workers =1;
////		bool spin = false;
////
////		net::io_context ioc{ 1 };
////		tcp::acceptor acceptor{ ioc, {address, port} };
////
////		std::list<http_worker> workers;
////		for (int i = 0; i < num_workers; ++i)
////		{
////			workers.emplace_back(acceptor, doc_root);
////			workers.back().start();
////		}
////
////		if (spin)
////			for (;;) ioc.poll();
////		else
////			ioc.run();
////	}
////	catch (const std::exception& e)
////	{
////		std::cerr << "Error: " << e.what() << std::endl;
////		return EXIT_FAILURE;
////	}
////}
//
////#include <iostream>
////#include <string>
////
////void display(std::string&& str)
////{
////	std::cout << str << std::endl;
////}
////
////void display1(std::string str)
////{
////	std::cout << str << std::endl;
////}
////
////int main()
////{
////	std::string str = "1234fw";
////	//display(std::move(str));
////	display1(str);
////	int i = 10;
////}
////
////#include<iostream>
////
////void test(int i)
////{
////	if (i ==0){
////		throw std::logic_error("User information does not exist");
////	}
////}
////
////void display()
////{
////	try
////	{
////		test(0);
////	}
////	catch (const std::exception&e)
////	{
////		std::cout << e.what() << std::endl;
////	}
////}
////
////int main()
////{
////	display();
////}
//
////#include<iostream>
////#include <vector>
////#include <string>
////
////std::string hex_encode(std::uint8_t const* first, std::uint8_t const* const last) {
////	static const char myDigits[] = "0123456789ABCDEF";
////	std::string myResult;
////	auto dist = std::distance(first, last);
////	myResult.reserve(dist * 2);
////	while (first != last) {
////		auto byte = *first++;
////		myResult.push_back(myDigits[byte >> 4]);
////		myResult.push_back(myDigits[byte & 0xf]);
////	}
////	return myResult;
////}
////
////template<class Iter>
////std::string hex_encode(Iter first, Iter last) {
////	return hex_encode(reinterpret_cast<std::uint8_t const*>(std::addressof(*first)),
////		reinterpret_cast<std::uint8_t const*>(std::addressof(*last)));
////}
////
////int main()
////{
////	int i = 3;
////	if (i |3 ==1){
////		int j = 10;
////	}
////
////	//std::string str = "0123456789";
////	//std::string hex_str = hex_encode((std::uint8_t const*)&str[0],(std::uint8_t const*)&str[9]);
////	//int i = 10;
////
////	//std::vector<int>vec{ 1,2,3,4,5,6,7,8,9,10 };
////	//size_t dist = std::distance(vec.begin(), vec.end());//算出距离值 
////}
//
////#include<iostream>
////#include<array>
////#include<boost/beast/core.hpp>
////
////int main()
////{
////	boost::beast::flat_buffer buffer;
////	//buffer.max_size(200);
////	auto buf = buffer.prepare(202);
////
////	std::array<int, 3>vecs;
////	vecs[0]=1;
////	vecs[1] = 2;
////	vecs[2] = 3;
////
////	auto iter_begin = vecs.begin();
////	for (;iter_begin != vecs.end();++iter_begin){
////		std::cout << *iter_begin << std::endl;
////	}
////
////}
////
////#include<iostream>
////#include<tuple>
////#include<string>
////
////auto display()
////{
////	std::tuple<int, int>tuple = std::make_tuple<int, int>(1, 2);
////	return std::move(tuple);
////}
////
////std::string split_my_cookie(std::string&& str)
////{
////	std::string copy_str = std::move(str);
////
////	auto beg_pos = copy_str.find("cj-newtest=");
////
////	auto end_pos = copy_str.find(";", beg_pos+1);
////	end_pos++;
////	std::string spilt_str = copy_str.substr(beg_pos, end_pos - beg_pos);
////	return std::move(spilt_str);
////}
////
////int main()
////{
////	std::string cookie = "12ww1; cj-newtest=CQoPFggWCBYJCggKCAgBCQxsCQ0NAA; PHPSESSID=470a55e3cf45f6d440351efdd10a5b65; mysid=7f8aec4537b9d367e782820f296c2023";
////	std::string str = split_my_cookie(std::move(cookie));
//////	//int v1, v2;
//////	//std::tie(v1,v2)=display();
//////	//const auto [v1, v2] = display();
//////
//////	auto s{ 1 };
//////
//////
//////	std::pair<int, int>pa;
//////	pa.first = 1;
//////	pa.second = 2;
//////
//////	//auto [key, value] = pa;
//////
////////	std::cout << key << value << std::endl;
////
////}
//
////#include <iostream>
////#include <string>
////
//////template <auto value> void foo() {
//////	std::cout << value << std::endl;
//////	return;
//////}
////
////std::string display()
////{
////	std::string str = "hello world";
////	return std::move(str);
////}
////
//////c++14
////decltype(auto)display1() {
////	return display();
////}
////
//////c++14
////auto display2() {
////	return display1();
////}
////
//////c++11
////auto display3()->decltype(display2()) {
////	return display2();
////}
////
////int main()
////{
////	//foo<10>();
////	int i = 10;
////}
////
////#include <boost/beast/core.hpp>
////#include <boost/beast/http.hpp>
////#include <boost/beast/ssl.hpp>
////#include <boost/beast/websocket.hpp>
////#include <boost/beast/version.hpp>
////#include <boost/asio/bind_executor.hpp>
////#include <boost/asio/dispatch.hpp>
////#include <boost/asio/signal_set.hpp>
////#include <boost/asio/steady_timer.hpp>
////#include <boost/asio/strand.hpp>
////#include <boost/make_unique.hpp>
////#include <boost/optional.hpp>
////#include <algorithm>
////#include <cstdlib>
////#include <functional>
////#include <iostream>
////#include <memory>
////#include <string>
////#include <thread>
////#include <vector>
////
////namespace beast = boost::beast;                 // from <boost/beast.hpp>
////namespace http = beast::http;                   // from <boost/beast/http.hpp>
////namespace websocket = beast::websocket;         // from <boost/beast/websocket.hpp>
////namespace net = boost::asio;                    // from <boost/asio.hpp>
////namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
////using tcp = boost::asio::ip::tcp;               // from <boost/asio/ip/tcp.hpp>
////
////void
////fail(beast::error_code ec, char const* what)
////{
////	// ssl::error::stream_truncated, also known as an SSL "short read",
////	// indicates the peer closed the connection without performing the
////	// required closing handshake (for example, Google does this to
////	// improve performance). Generally this can be a security issue,
////	// but if your communication protocol is self-terminated (as
////	// it is with both HTTP and WebSocket) then you may simply
////	// ignore the lack of close_notify.
////	//
////	// https://github.com/boostorg/beast/issues/38
////	//
////	// https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
////	//
////	// When a short read would cut off the end of an HTTP message,
////	// Beast returns the error beast::http::error::partial_message.
////	// Therefore, if we see a short read here, it has occurred
////	// after the message has been completed, so it is safe to ignore it.
////
////	if (ec == net::ssl::error::stream_truncated)
////		return;
////
////	std::cerr << what << ": " << ec.message() << "\n";
////}
////
////
////// Detects SSL handshakes
////class detect_session : public std::enable_shared_from_this<detect_session>{
////	beast::ssl_stream<beast::tcp_stream> stream_;
////	ssl::context& ctx_;
////
////	std::shared_ptr<std::string const> doc_root_;
////	beast::flat_buffer buffer_;
////
////public:
////	explicit
////		detect_session(
////			tcp::socket&& socket,
////			ssl::context& ctx,
////			std::shared_ptr<std::string const> const& doc_root)
////		:ctx_(ctx)
////		,stream_(std::move(socket),ctx)
////		,doc_root_(doc_root)
////	{
////	}
////
////	// Launch the detector
////	void
////		run()
////	{
////		// We need to be executing within a strand to perform async operations
////		// on the I/O objects in this session. Although not strictly necessary
////		// for single-threaded contexts, this example code is written to be
////		// thread-safe by default.
////		net::dispatch(
////			stream_.get_executor(),
////			beast::bind_front_handler(
////				&detect_session::on_run,
////				this->shared_from_this()));
////	}
////
////	void
////		on_run()
////	{
////		// Set the timeout.
////		//stream_.expires_after(std::chrono::seconds(30));
////
////		beast::async_detect_ssl(
////			stream_,
////			buffer_,
////			beast::bind_front_handler(
////				&detect_session::on_detect,
////				this->shared_from_this()));
////	}
////
////	void
////		on_detect(beast::error_code ec, bool result)
////	{
////		if (ec) {
////			std::cout << ec.message() << std::endl;
////		}
////
////		if (result) {
////			return;
////		}
////
////		// Launch plain session
////	}
////
////};
////
////// Accepts incoming connections and launches the sessions
////class listener : public std::enable_shared_from_this<listener>
////{
////	net::io_context& ioc_;
////	ssl::context& ctx_;
////	tcp::acceptor acceptor_;
////	std::shared_ptr<std::string const> doc_root_;
////
////public:
////	listener(
////		net::io_context& ioc,
////		ssl::context& ctx,
////		tcp::endpoint endpoint,
////		std::shared_ptr<std::string const> const& doc_root)
////		: ioc_(ioc)
////		, ctx_(ctx)
////		, acceptor_(net::make_strand(ioc))
////		, doc_root_(doc_root)
////	{
////		beast::error_code ec;
////
////		// Open the acceptor
////		acceptor_.open(endpoint.protocol(), ec);
////		if (ec)
////		{
////			fail(ec, "open");
////			return;
////		}
////
////		// Allow address reuse
////		acceptor_.set_option(net::socket_base::reuse_address(true), ec);
////		if (ec)
////		{
////			fail(ec, "set_option");
////			return;
////		}
////
////		// Bind to the server address
////		acceptor_.bind(endpoint, ec);
////		if (ec)
////		{
////			fail(ec, "bind");
////			return;
////		}
////
////		// Start listening for connections
////		acceptor_.listen(
////			net::socket_base::max_listen_connections, ec);
////		if (ec)
////		{
////			fail(ec, "listen");
////			return;
////		}
////	}
////
////	// Start accepting incoming connections
////	void
////		run()
////	{
////		do_accept();
////	}
////
////private:
////	void
////		do_accept()
////	{
////		// The new connection gets its own strand
////		acceptor_.async_accept(
////			net::make_strand(ioc_),
////			beast::bind_front_handler(
////				&listener::on_accept,
////				shared_from_this()));
////	}
////
////	void
////		on_accept(beast::error_code ec, tcp::socket socket)
////	{
////		if (ec)
////		{
////			fail(ec, "accept");
////		}
////		else
////		{
////			// Create the detector http_session and run it
////			std::make_shared<detect_session>(
////				std::move(socket),
////				ctx_,
////				doc_root_)->run();
////		}
////
////		// Accept another connection
////		do_accept();
////	}
////};
////
//////------------------------------------------------------------------------------
////
////int main(int argc, char* argv[])
////{
////	auto const address = net::ip::make_address("0.0.0.0");
////	auto const port = static_cast<unsigned short>(std::atoi("80"));
////	auto const doc_root = std::make_shared<std::string>("/");
////	auto const threads = std::max<int>(1,0);
////
////	// The io_context is required for all I/O
////	net::io_context ioc{ threads };
////
////	// The SSL context is required, and holds certificates
////	ssl::context ctx{ ssl::context::tlsv12 };
////
////	// Create and launch a listening port
////	std::make_shared<listener>(
////		ioc,
////		ctx,
////		tcp::endpoint{ address, port },
////		doc_root)->run();
////
////	// Capture SIGINT and SIGTERM to perform a clean shutdown
////	net::signal_set signals(ioc, SIGINT, SIGTERM);
////	signals.async_wait(
////		[&](beast::error_code const&, int)
////		{
////			// Stop the `io_context`. This will cause `run()`
////			// to return immediately, eventually destroying the
////			// `io_context` and all of the sockets in it.
////			ioc.stop();
////		});
////
////	// Run the I/O service on the requested number of threads
////	std::vector<std::thread> v;
////	v.reserve(threads - 1);
////	for (auto i = threads - 1; i > 0; --i)
////		v.emplace_back(
////			[&ioc]
////			{
////				ioc.run();
////			});
////	ioc.run();
////
////	// (If we get here, it means we got a SIGINT or SIGTERM)
////
////	// Block until all the threads exit
////	for (auto& t : v)
////		t.join();
////
////	return EXIT_SUCCESS;
////}
////
////#include <iostream>
////#include <string>
////#include <vector>
////#include <algorithm>
////#include<map>
////#include <boost/algorithm/string.hpp>
////
////void display(std::string str)
////{
////	std::cout << str << std::endl;
////}
////
////int main()
////{
////	std::string s = "HELLO";
////	display(s);
////	std::string out;
////	//std::transform(s.begin(), s.end(), std::back_inserter(out), std::toupper);
////	//std::transform(s.begin(), s.end(), std::back_inserter(out),std::tolower);
////
////	std::map<int, int>ms;
////	ms.insert({ 1,2 });
////	ms[1] = 2;
////
////	std::vector<std::string>url_white_list;
////	url_white_list.push_back("/login/*");
////	std::string target_str ="/sddwwww";
////
////	//url_white_list.push_back("/login/*");
////	//std::string target_str = "/login/test/123";
////
////	auto iter_find = std::find_if(url_white_list.begin(),
////		url_white_list.end(), [target_str](const std::string& str) {
////			if (str == target_str) {
////				return true;
////			}
////
////			if (str =="/*"){
////				return true;
////			}
////
////			std::string temp_str = str;
////			auto pos = temp_str.find("*");
////			if (pos != std::string::npos){
////				std::string split_str1 = temp_str.substr(0, pos);
////
////				std::string temp_str = str;
////				bool is_find = false;
////
////				std::size_t pos = 0;
////				std::size_t start_pos = 0;
////				std::string split_str2;
////
////				while ((pos = target_str.find("/", start_pos))
////					!= std::string::npos) {
////					
////					temp_str = target_str.substr(start_pos, pos - start_pos);
////					if (pos >= 0) {
////						temp_str += "/";
////					}
////
////					split_str2 += temp_str;
////					if (split_str2 == split_str1) {
////						is_find = true;
////						break;
////					}
////
////					start_pos = (pos + 1);
////				}
////			}
////
////			return false;
////		});
////
////
////	int i = 10;
////}
//
////#include <boost/asio.hpp>
////#include <cpp_redis/cpp_redis>
////#include <iostream>
////
////int main()
////{
////	cpp_redis::active_logger = std::unique_ptr<cpp_redis::logger>(new cpp_redis::logger);
////	cpp_redis::client client;
////
////	try
////	{
////		//cpp_redis::network::set_default_nb_workers(2);
////		//std::vector<std::string>vecs;
////		//std::string ip_port= "111.229.244.148:6379";
////		//vecs.push_back(ip_port);
////		//client.cluster_addslots(vecs);
////		//client.sync_commit();
////		//client.add_sentinel("111.229.244.148", 6379);
////		//client.connect("master", nullptr);
////		client.connect("192.168.5.95", 6379);
////
////		std::future<cpp_redis::reply> setnx;
////		if(client.is_connected()) {
////			//client.setex("yinpinghua", 60, "123");
////			setnx = client.setnx("yinpinghua", "123");//判断子健值是否存在
////		}
////
////		client.sync_commit();
////		std::cout << setnx.get() << std::endl;;
////	}
////	catch (const std::exception&ec)
////	{
////		std::cout << ec.what() << std::endl;
////		int i = 10;
////	}
////
////	int i = 10;
////}
//
////#include <iostream>
////#include <string>
////#include <algorithm>
////#include <memory>
////#include<map>
////
////class A {
////public:
////	A() {
////		std::cout << "A()" << std::endl;
////	}
////
////	~A() {
////		std::cout << "~A()" << std::endl;
////	}
////};
////
////int main()
////{
////	std::map<int, int>mints;
////	mints[1] = 2;
////	//mints[2] = 3;
////	mints.erase(2);
////
////	std::size_t g_index = 0;
////	for (int i = 0;i < 3000;++i) {
////		int ret = (g_index % 3) + 1;
////		if (ret >3){
////			break;
////		}
////
////		std::cout << ret << std::endl;
////
////		++g_index;
////	}
////
////	std::shared_ptr<A> ptr = nullptr;
////	auto ptr1 = std::make_shared<A>();
////	ptr =std::move(ptr1);
////
////	for (int n : {0, 1, 2, 3, 4, 5}) // 初始化器可以是花括号初始化器列表
////		std::cout << n << ' ';
////
//// 	std::string str = "hello";
////	std::string out_str;
////	std::transform(str.begin(),str.end(),std::back_inserter(out_str),std::toupper);
////
////	int i = 10;
////	auto ptr2 = std::make_shared<A>();
////	//ptr = nullptr;
////	ptr = std::move(ptr2);
////
////}
////
////#include "listener.h"
////
////int main(int argc, char* argv[])
////{
////	auto const address = net::ip::make_address("0.0.0.0");
////	auto const port = 443;
////	auto const doc_root = std::make_shared<std::string>(".");
////	auto const threads = 24;
////
////	// The io_context is required for all I/O
////	net::io_context ioc{ threads };
////	//count_thread count_t;
////	// The SSL context is required, and holds certificates
////	ssl::context ctx{ ssl::context::tlsv12 };
////	std::ifstream open("./key.key", std::ios::ate);
////	if (!open.is_open()) {
////		return 0;
////	}
////
////	std::size_t size = open.tellg();
////	open.seekg(std::ios::beg);
////	std::string key_data;
////	key_data.resize(size);
////	open.read(&key_data[0], size);
////	open.close();
////
////	ctx.use_private_key(
////		std::move(boost::asio::buffer(key_data.data(), key_data.size())),
////		boost::asio::ssl::context::file_format::pem);
////	open.open("./crt.crt", std::ios::ate);
////	if (!open.is_open()) {
////		return 0;
////	}
////
////	std::string cert_data;
////	size = open.tellg();
////	cert_data.resize(size);
////	open.seekg(std::ios::beg);
////	cert_data.resize(size);
////	open.read(&cert_data[0], size);
////	open.close();
////
////	ctx.use_certificate_chain(
////		std::move(boost::asio::buffer(cert_data.data(), cert_data.size())));
////
////	// Create and launch a listening port
////	std::make_shared<listener>(
////		ioc,
////		ctx,
////		tcp::endpoint{ address, port })->run();
////
////	// Run the I/O service on the requested number of threads
////	std::vector<std::thread> v;
////	v.reserve(threads - 1);
////	for (auto i = threads - 1; i > 0; --i)
////		v.emplace_back(
////			[&ioc]
////			{
////				ioc.run();
////			});
////	ioc.run();
////
////	return EXIT_SUCCESS;
////}
////
////#include <boost/archive/text_oarchive.hpp> 
////#include <boost/archive/text_iarchive.hpp> 
////#include <boost/serialization/vector.hpp> 
////
////#include <iostream> 
////#include <sstream> 
////#include <vector>
////
////class A
////{
////public:
////	A(size_t age,size_t sex) :age_(age), sex_(sex){
////		for (int i =0;i<10;++i){
////			vecs_.push_back(i);
////		}
////	}
////	A() {
////		for (int i = 0;i < 10;++i) {
////			vecs_.push_back(i);
////		}
////	}
////	~A() = default;
////private:
////private:
////	friend class boost::serialization::access;
////
////	template <typename Archive>
////	void serialize(Archive& ar, const unsigned int version)
////	{
////		ar& age_;
////		ar& sex_;
////		ar& vecs_;
////	}
////
////private:
////	size_t age_ =1;
////	size_t sex_=2;
////	std::vector<int>vecs_;
////};
////std::stringstream ss;
////
////void save()
////{
////	boost::archive::text_oarchive oa(ss);
////	A a(100,200);
////	oa << a;
////}
////
////void load()
////{
////	boost::archive::text_iarchive ia(ss);
////	std::string str_buf = ss.str();
////	A  a;
////	ia >> a;
////}
////
////int main()
////{
////	std::string body = "123";
////	std::stringstream ss1(&body[0]);
////	std::string str1 = ss1.str();
////	save();
////	load();
////}
//
////
////#include<iostream>
////class A
////{
////public:
////	A() {
////		std::cout << "A()" << std::endl;
////	}
////
////	~A() {
////		std::cout << "~A()" << std::endl;
////	}
////
////	void display() {
////		std::cout << "A" << std::endl;
////	}
////};
////
////A visitorAddressMag_;
////
////A* GetVisitorAddressMag()
////{
////	return &visitorAddressMag_;
////}
////
////int main()
////{
////	GetVisitorAddressMag()->display();
////	GetVisitorAddressMag()->display();
////}
//
////#include <iostream>
////#include <string>
////#include <boost/uuid/uuid.hpp>
////#include <boost/uuid/uuid_io.hpp>
////#include <boost/uuid/uuid_generators.hpp>
////int main()
////{
////	for (size_t i = 0; i < 100; i++)
////	{
////		boost::uuids::uuid uuid = boost::uuids::random_generator()(); // 这里是两个() ，因为这里是调用的 () 的运算符重载
////		const std::string tmp_uuid = boost::uuids::to_string(uuid);
////		std::cout << tmp_uuid << std::endl;
////	}
////
////}
//
////#include <chrono>
////#include <iostream>
////
////std::int64_t get_time_stamp()
////{
////	std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> tp =
////		std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
////
////	auto tmp = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch());
////	return tmp.count();
////}
////
////int main()
////{
////	auto time_stamp = get_time_stamp();
////	auto time_stamp1 = time_stamp + 120;
////}
//
////#include <iostream>
////#include <vector>
////#include "BufferPtr.h"
////CCharBufferPtr buffer;
////
////
////void copy1(CCharBufferPtr&& str)
////{
////	CCharBufferPtr buf1 = std::move(str);
////}
////int main()
////{
////	{
////		std::vector<CCharBufferPtr>vecs;
////		std::string str = "111";
////		std::string str2 = "111";
////		buffer.Cat(str.c_str(), str.size());
////
////		{
////			CCharBufferPtr buf112;
////			buf112.Cat(str2.c_str(), str2.size());
////			buf112 = std::move(buffer);
////		}
////
////		//vecs.push_back(std::move(buffer));
////		//auto&& Tmp = std::move(buffer);
////
////		//CCharBufferPtr buffer1 = std::move(buffer);
////		//copy1(std::move(buffer));
////	}
////
////
////	int i = 100;
////	int i1 = 0;
////}
////
////#include<iostream>
////#include<string>
////#include <vector>
////#include <sstream>
////#include <chrono>
////#include <boost/archive/text_oarchive.hpp> 
////#include <boost/archive/text_iarchive.hpp> 
////#include <boost/serialization/vector.hpp> 
////#include "BufferPtr.h"
////
////class ip_msg
////{
////public:
////	ip_msg() = default;
////	~ip_msg() = default;
////	void insert_ip(const std::string& ip)
////	{
////		ips_.push_back(ip);
////	}
////private:
////	friend class boost::serialization::access;
////
////	template <typename Archive>
////	void serialize(Archive& ar, const unsigned int version)
////	{
////		ar& ips_;
////	}
////private:
////	std::vector<std::string>ips_;
////};
////
////std::int64_t get_time_stamp()
////{
////	std::chrono::time_point<std::chrono::system_clock, std::chrono::seconds> tp =
////		std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now());
////
////	auto tmp = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch());
////	return tmp.count();
////}
////
////int main()
////{
////	auto begin = get_time_stamp();
////	std::string ip = "255.255.255.255";
////	ip_msg ips;
////	for (int i = 0;i < 900000;++i)
////	{
////		ips.insert_ip(ip);
////	}
////
////
////	std::stringstream ss;
////	boost::archive::text_oarchive oa(ss);
////	oa << ips;
////
////	std::string str = ss.str();
////
////	auto end = get_time_stamp();
////
////	auto seconds = end - begin;
////	std::cout << seconds <<" "<<str.size() << std::endl;
////	system("pause");
////}
////
////#include <iostream>
////#include <algorithm>
////#include <vector>
////#include <string>
////
////int main()
////{
////	std::vector<std::string>strs;
////	strs.push_back("/upload/user/user1/user2/a/b/*");
////	bool is_white = false;
////	std::string target = "/upload/user/user1/user2/a/b/c";
////	if (target != "/") {
////		std::string target_str = target;
////		auto iter_find = std::find_if(strs.begin(),
////			strs.end(),
////			[target_str = std::move(target_str)](const std::string& str) {
////			if (str == target_str) {
////				return true;
////			}
////
////			if (str == "/*") {
////				return true;
////			}
////
////			std::string temp_str = str;
////			bool is_find = false;
////
////			auto pos = temp_str.find("*");
////			if(pos != std::string::npos) {
////				std::string split_str1 = temp_str.substr(0, pos);
////				std::size_t pos = 0;
////				std::size_t start_pos = 1;
////				std::string split_str2;
////				while ((pos = target_str.find("/", start_pos))
////					!= std::string::npos) {
////					size_t sub_pos = pos - start_pos;
////					temp_str = "";
////					if (sub_pos > 0) {
////						if (start_pos ==1){
////							temp_str = "/";
////						}
////
////						temp_str += target_str.substr(start_pos, sub_pos);
////						temp_str += "/";
////					}
////
////					split_str2 += temp_str;
////					if (split_str2 == split_str1) {
////						is_find = true;
////						break;
////					}
////
////					start_pos = (pos + 1);
////				}
////			}
////
////			return is_find;
////		});
////
////		if (iter_find != strs.end()) {
////			is_white = true;
////		}
////	}
////
////
////	int i = 10;
////}
////
////#include<iostream>
////#include <string>
////
////constexpr int i = 1 * 2;
////int main()
////{
////#ifdef DEBUG
////	std::cout << "debug" << std::endl;
////#else
////	std::cout << "release" << std::endl;
////#endif
////}
////
////#include <iostream>
////#include "manage_ipdb.hpp"
////
////int main()
////{
////	std::string client_ip = "125.119.78.224";
////	//std::string client_ip = "2a0c:640::216:3eff:fec0:1862";
////	std::string country_str, region_str, city_str, isp_str;
////	manage_ipdb::instance().init_ipdb("./b.ipdb");
////	manage_ipdb::instance().get_ipdb_info(country_str, region_str, city_str, isp_str, client_ip);
////}
////
////
////#include <iostream>
////#include <sstream>
////#define  _WINSOCK_DEPRECATED_NO_WARNINGS
////#ifdef _WIN32
////#include <WS2tcpip.h>
////#else
////#include <arpa/inet.h>
////#endif
////
////int inet4_pton1(const char* cp, uint32_t& ap) {
////	struct in_addr addr {};
////	int ret = inet_pton(AF_INET, cp, &addr);
////	if (ret == 1) {
////		ap = addr.S_un.S_addr;
////	}
////
////	return 1;
////}
////int inet4_pton(const char* cp, uint32_t& ap) {
////	struct in_addr addr {};
////	int ret = inet_pton(AF_INET, cp, &addr);
////	if (ret ==1){
////		ap = addr.S_un.S_addr;
////	}
////
////	return 1;
////
////	uint32_t acc = 0;
////	uint32_t  dots = 0;
////	uint32_t  addr = 0;
////	uint32_t index = 0;
////
////	do {
////		char cc = *cp;
////		if (cc >= '0' && cc <= '9') {
////			acc = acc * 10 + (cc - '0');
////		}
////		else if (cc == '.' || cc == '\0') {
////			if (++dots > 3 && cc == '.') {
////				return 0;
////			}
////			/* Fall through */
////
////			if (acc > 255) {
////				return 0;
////			}
////
////			addr += (acc << (index * 8));
////			从左往右，低位放
////			addr = addr << 8 | acc; // 这句是精华,每次将当前值左移八位加上后面的值
////			acc = 0;
////			++index;
////		}
////	} while (*cp++);
////
////	 Normalize the address 
////	if (dots < 3) {
////		addr <<= 8 * (3 - dots);
////	}
////
////	ap = addr;
////	return 1;
////}
////
////void inet4_ntop(uint32_t value, std::string& str)
////{
////	in_addr addr;
////	addr.s_addr = value;
////	str = inet_ntoa(addr);
////
////
////	constexpr int inet_addrlen = 20;
////	str.resize(inet_addrlen);
////
////	Intel 机器是高位存高位，低位存低位，因此数组越大越是低位
////	unsigned char* temp_addrptr = (unsigned char*)(&value);
////	snprintf(&str[0], str.size(), "%d.%d.%d.%d",
////		*(temp_addrptr + 3), *(temp_addrptr + 2), *(temp_addrptr + 1), *(temp_addrptr + 0));
////
////
////	size_t size = strlen(str.c_str());
////
////	str.resize(size);
////}
////
////
////static void inet6_ntop(const u_char* src, std::string& dst) {
////	constexpr  int  NS_IN6ADDRSZ = 16;
////	constexpr   int NS_INT16SZ = 2;
////	char tmp[100] = { 0 };
////	struct { int base, len; } best, cur;
////	std::size_t words[NS_IN6ADDRSZ / NS_INT16SZ] = { 0 };
////
////	memset(words, '\0', sizeof words);
////	for (int i = 0; i < NS_IN6ADDRSZ; i += 2) {
////		words[i / 2] = (src[i] << 8) | src[i + 1];
////	}
////
////	best.base = -1;
////	cur.base = -1;
////	best.len = 0;
////	cur.len = 0;
////	for (int i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
////		if (words[i] == 0) {
////			if (cur.base == -1) {
////				cur.base = i, cur.len = 1;
////			}
////			else {
////				cur.len++;
////			}
////		}
////		else {
////			if (cur.base != -1) {
////				if (best.base == -1 || cur.len > best.len) {
////					best = cur;
////				}
////
////				cur.base = -1;
////			}
////		}
////	}
////	if (cur.base != -1) {
////		if (best.base == -1 || cur.len > best.len) {
////			best = cur;
////		}
////	}
////	if (best.base != -1 && best.len < 2) {
////		best.base = -1;
////	}
////
////	/*
////	 * Format the result.
////	 */
////	char* tp = tmp;
////	for (int i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
////		/* Are we inside the best run of 0x00's? */
////		if (best.base != -1 && i >= best.base &&
////			i < (best.base + best.len)) {
////			if (i == best.base) {
////				*tp++ = ':';
////			}
////
////			continue;
////		}
////		/* Are we following an initial run of 0x00s or any real hex? */
////		if (i != 0) {
////			*tp++ = ':';
////		}
////
////		/* Is this address an encapsulated IPv4? */
////		if (i == 6 && best.base == 0 &&
////			(best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
////			std::string temp;
////			temp.resize(20);
////			memcpy(&temp[0], (char*)src + 12, 4);
////
////			uint32_t value = 0;
////			uint32_t* ptr = (uint32_t*)temp.data();
////			value = *ptr;
////
////			inet4_ntop(value, temp);
////			std::size_t len = strlen(temp.c_str());
////			memcpy(tp, temp.c_str(), len);
////			tp += len;
////			break;
////		}
////
////		std::stringstream sstream;
////		sstream << std::hex << words[i];
////		std::size_t len = strlen(sstream.str().c_str());
////		memcpy(tp, sstream.str().c_str(), len);
////		tp += len;
////	}
////	/* Was it a trailing run of 0x00's? */
////	if (best.base != -1 && (best.base + best.len) == (NS_IN6ADDRSZ / NS_INT16SZ)) {
////		*tp++ = ':';
////	}
////
////	*tp++ = '\0';
////
////	std::size_t len = strlen(tmp);
////	dst.resize(len);
////	memcpy(&dst[0], tmp, len);
////}
////
////
////int inet6_pton(const std::string&src_addr,const u_char* ip, int bit_count)
////{
////	struct in6_addr temp_addr {};
////	int ret = inet_pton(AF_INET6, src_addr.c_str(), &temp_addr);
////	if (ret ==1){
////		ip = temp_addr.s6_addr;
////		bit_count = 128;
////	}
////
////}
////
////int main()
////{
////	std::string addr = "127.0.0.1";
////	std::string addr100;
////	addr100.resize(20);
////	uint32_t value;
////	uint32_t  value1;
////	inet4_pton(addr.c_str(), value);
////	std::cout << value << std::endl;
////
////	inet4_pton1(addr.c_str(), value1);
////
////	inet4_ntop(value, addr100);
////	std::string addr200;
////	inet4_ntop(value, addr200);
////	std::cout << addr100 << std::endl;
////
////	std::string ipv6_str = "2000:0000:0000:0000:0001:2345:6789:abcd";
////	struct in6_addr ip;
////	char* addr1, * addr2, * addr3;
////
////	addr1 = _strdup("2000:0000:0000:0000:0001:2345:6789:abcd");
////	addr2 = _strdup("2a01:198:603:0::");
////	addr3 = _strdup("2a01::");
////
////	inet_pton(AF_INET6, addr1, &ip);
////	struct in6_addr ip1;
////	ip1.u = ip.u;
////	std::string sss;
////	sss.resize(100);
////	inet_ntop(AF_INET6,&ip1,&sss[0], INET6_ADDRSTRLEN);
////	std::string sss1;
////
////	inet6_ntop(ip1.u.Byte, sss1);
////
////	printf("0x%x\n", ip.s_addr);
////
////	in_addr tmp1111;
////	tmp1111.s_addr = ip.s_addr;
////	std::string ssss =inet_ntoa(tmp1111);
////
////	inet_pton(AF_INET6, addr2, &ip);
////	printf("0x%x\n", ip.s_addr);
////
////	inet_pton(AF_INET6, addr3, &ip);
////	printf("0x%x\n", ip.s_addr);
////
////	struct in6_addr addr6 {};
////	if (inet_pton(AF_INET, addr.c_str(), &addr4)==1) {
////		uint32_t value = addr4.S_un.S_addr;
////		//inet_ntop(AF_INET, addr1.c_str(),value);
////		std::cout << "ipv4地址" << std::endl;
////		return 0;
////	}
////
////	else if (inet_pton(AF_INET6, addr.c_str(), &addr6)) {
////		if (!is_ipv6_support()) {
////			std::cout << "not support ipv6" << std::endl;
////			return std::move(str);
////		}
////
////		node = search((const u_char*)&addr6.s6_addr, g_ipv6_bit);
////	}
////}
//
//
//
////#include <iostream>
////#include <sstream>
////#include <stdio.h>
////#ifdef _WIN32
////#define _WINSOCK_DEPRECATED_NO_WARNINGS
////#include <WS2tcpip.h>
////#else
////#include <arpa/inet.h>
////#endif
////
////int inet4_pton(const char* cp, uint32_t& ap) {
////	uint32_t acc = 0;
////	uint32_t  dots = 0;
////	uint32_t  addr = 0;
////	uint32_t index = 0;
////
////	do {
////		char cc = *cp;
////		if (cc >= '0' && cc <= '9') {
////			acc = acc * 10 + (cc - '0');
////		}
////		else if (cc == '.' || cc == '\0') {
////			if (++dots > 3 && cc == '.') {
////				return 0;
////			}
////			/* Fall through */
////
////			if (acc > 255) {
////				return 0;
////			}
////
////			addr += (acc << (index * 8));//各平台统一
////			//从左往右，低位放
////			//addr = addr << 8 | acc; // 这句是精华,每次将当前值左移八位加上后面的值
////			++index;
////			acc = 0;
////		}
////	} while (*cp++);
////
////	// Normalize the address 
////	if (dots < 3) {
////		addr <<= 8 * (3 - dots);
////	}
////
////	ap = addr;
////	return 1;
////
////}
////
////void inet4_ntop(uint32_t value, std::string& str)
////{
////	in_addr addr;
////	addr.s_addr = value;
////	str = inet_ntoa(addr);
////
////	//constexpr int inet_addrlen = 20;
////	//str.resize(inet_addrlen);
////
////	////Intel 机器是高位存高位，低位存低位，因此数组越大越是低位
////	//unsigned char* temp_addrptr = (unsigned char*)(&value);
////	//snprintf(&str[0], str.size(), "%d.%d.%d.%d",
////	//	*(temp_addrptr + 0), *(temp_addrptr + 1), *(temp_addrptr + 2), *(temp_addrptr + 3));
////
////
////	//size_t size = strlen(str.c_str());
////
////	//str.resize(size);
////}
////
////int inet6_pton(const char* src, std::uint8_t* dst) {
////	if (src == nullptr) {
////		return 0;
////	}
////
////	constexpr  char  xdigits_l[] = "0123456789abcdef";
////	constexpr  char  xdigits_u[] = "0123456789ABCDEF";
////	const      char* xdigits = nullptr;
////	const      char* curtok = nullptr;
////	constexpr  int  NS_IN6ADDRSZ = 16;
////	constexpr   int NS_INT16SZ = 2;
////	std::uint8_t tmp[NS_IN6ADDRSZ] = { 0 };
////	std::uint8_t* tp = tmp;
////	std::uint8_t* endp = nullptr;
////	std::uint8_t* colonp = nullptr;
////	endp = tp + NS_IN6ADDRSZ;
////
////	/* Leading :: requires some special handling. */
////	if (*src == ':') {
////		if (*++src != ':') {
////			return 0;
////		}
////	}
////
////	int              seen_xdigits = 0;
////	std::size_t    val = 0;
////	char  ch = 0;
////	while ((ch = *src++) != '\0') {
////		const char* pch = nullptr;
////
////		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL) {
////			pch = strchr((xdigits = xdigits_u), ch);
////		}
////
////		if (pch != NULL) {
////			val <<= 4;
////			val |= (pch - xdigits);
////			if (++seen_xdigits > 4) {
////				return 0;
////			}
////
////			continue;
////		}
////
////		if (ch == ':') {
////			curtok = src;
////			if (!seen_xdigits) {
////				if (colonp != nullptr) {
////					return 0;
////				}
////
////				colonp = tp;
////				continue;
////			}
////			else if (*src == 0) {
////				return 0;
////			}
////
////			if (tp + NS_INT16SZ > endp) {
////				return 0;
////			}
////
////			*tp++ = (u_char)(val >> 8) & 0xff;	//放在高位上
////			*tp++ = (u_char)val & 0xff; //放在低位上
////			seen_xdigits = 0;
////			val = 0;
////			continue;
////		}
////
////		if (ch == '.' && ((tp + 4) <= endp)) {
////			uint32_t value = 0;
////			if (inet4_pton(curtok, value)) {
////				unsigned char* buf = (unsigned char*)&value;
////				memcpy(tp, buf, 4);
////				tp += 4;
////				seen_xdigits = 0;
////				break;  /*%< '\\' was seen by inet_pton4(). */
////			}
////		}
////
////		return 0;
////	}
////
////	if (seen_xdigits) {
////		if (tp + NS_INT16SZ > endp) {
////			return 0;
////		}
////
////		*tp++ = (u_char)(val >> 8) & 0xff;
////		*tp++ = (u_char)val & 0xff;
////	}
////
////	if (colonp != NULL) {
////		if (tp == endp) {
////			return 0;
////		}
////
////		const std::size_t n = tp - colonp;
////		for (int i = 1; i <= n; i++) {
////			endp[-i] = colonp[n - i];
////			colonp[n - i] = 0;
////		}
////
////		tp = endp;
////	}
////
////	if (tp != endp) {
////		return 0;
////	}
////
////	memcpy(dst, tmp, NS_IN6ADDRSZ);
////
////	return 1;
////}
////
////void inet6_ntop1(const u_char* src, std::string& dst) {
////	constexpr  int  NS_IN6ADDRSZ = 16;
////	constexpr   int NS_INT16SZ = 2;
////	char tmp[100] = { 0 };
////	struct { int base, len; } best, cur;
////	std::size_t words[NS_IN6ADDRSZ / NS_INT16SZ] = { 0 };
////
////	memset(words, '\0', sizeof words);
////	for (int i = 0; i < NS_IN6ADDRSZ; i += 2) {
////		words[i / 2] = (src[i] << 8) | src[i + 1];
////	}
////
////	best.base = -1;
////	cur.base = -1;
////	best.len = 0;
////	cur.len = 0;
////	for (int i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
////		if (words[i] == 0) {
////			if (cur.base == -1) {
////				cur.base = i, cur.len = 1;
////			}
////			else {
////				cur.len++;
////			}
////		}
////		else {
////			if (cur.base != -1) {
////				if (best.base == -1 || cur.len > best.len) {
////					best = cur;
////				}
////
////				cur.base = -1;
////			}
////		}
////	}
////	if (cur.base != -1) {
////		if (best.base == -1 || cur.len > best.len) {
////			best = cur;
////		}
////	}
////	if (best.base != -1 && best.len < 2) {
////		best.base = -1;
////	}
////
////	/*
////	 * Format the result.
////	 */
////	char* tp = tmp;
////	for (int i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
////		/* Are we inside the best run of 0x00's? */
////		if (best.base != -1 && i >= best.base &&
////			i < (best.base + best.len)) {
////			if (i == best.base) {
////				*tp++ = ':';
////			}
////
////			continue;
////		}
////		/* Are we following an initial run of 0x00s or any real hex? */
////		if (i != 0) {
////			*tp++ = ':';
////		}
////
////		/* Is this address an encapsulated IPv4? */
////		if (i == 6 && best.base == 0 &&
////			(best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
////			std::string temp;
////			temp.resize(20);
////			memcpy(&temp[0], (char*)src + 12, 4);
////
////			uint32_t value = 0;
////			uint32_t* ptr = (uint32_t*)temp.data();
////			value = *ptr;
////
////			inet4_ntop(value, temp);
////			std::size_t len = strlen(temp.c_str());
////			memcpy(tp, temp.c_str(), len);
////			tp += len;
////			break;
////		}
////
////		std::stringstream sstream;
////		sstream << std::hex << words[i];
////		std::size_t len = strlen(sstream.str().c_str());
////		memcpy(tp, sstream.str().c_str(), len);
////		tp += len;
////	}
////	/* Was it a trailing run of 0x00's? */
////	if (best.base != -1 && (best.base + best.len) == (NS_IN6ADDRSZ / NS_INT16SZ)) {
////		*tp++ = ':';
////	}
////
////	*tp++ = '\0';
////
////	std::size_t len = strlen(tmp);
////	dst.resize(len);
////	memcpy(&dst[0], tmp, len);
////}
////
////
////int main()
////{
////	/******ipv4测试*******/
////	std::string addr = "127.120.255.120";
////	std::string addr100;
////	addr100.resize(20);
////	uint32_t value;
////	inet4_pton(addr.c_str(), value);
////	std::cout << value << std::endl;
////
////	inet4_ntop(value, addr100);
////	std::cout << addr100 << std::endl;
////
////	///*******ipv6测试*******/
////	//char* addr1 = _strdup("2000:0000:0000:0000:0001:2345:6789:abcd");
////	char* addr1 = _strdup("2001:0:0:fb58:3c5a:65d:25ff:ecd");
////	struct in6_addr ip;
////	struct in6_addr ip1;
////	std::string str;
////	std::string sss;
////	//inet_pton(AF_INET6, addr1, &ip);
////	inet6_pton(addr1, (uint8_t*)&ip.u);
////	ip1.u = ip.u;
////	inet6_ntop1(ip.u.Byte, str);
////
////	sss.resize(100);
////	inet_ntop(AF_INET6, &ip1, &sss[0], INET6_ADDRSTRLEN);
////}
//
////#include <iostream>
////#include <string>
//////constexpr const std::string str1 = "56247";	  //constexpr 编译器决定 ，不会执行string构造函数
////
////
////constexpr const char *str = "12345";
////
////int main()
////{
////	std::cout << str << std::endl;
////}
//
////#include <iostream>
////#include <memory>
////#include <boost/asio.hpp>
////#include <boost/bind.hpp>
////
//////thanks kalven for tips/debugging
////
////using boost::asio::ip::tcp;
////
////class Session : public std::enable_shared_from_this<Session>
////{
////public:
////	explicit Session(tcp::socket&& temp_socket)
////		: socket(std::move(temp_socket)) {}
////
////	void start()
////	{
////		socket.async_read_some(
////			boost::asio::buffer(data, max_length),
////			boost::bind(&Session::handle_read,shared_from_this(),
////				boost::asio::placeholders::error,
////				boost::asio::placeholders::bytes_transferred));
////	}
////
////	void handle_read(const boost::system::error_code& err,
////		size_t bytes_transferred)
////	{
////		if (!err) {
////			std::cout << "recv: test" << std::endl;
////			socket.async_read_some(
////				boost::asio::buffer(data, max_length),
////				boost::bind(&Session::handle_read,shared_from_this(),
////					boost::asio::placeholders::error,
////					boost::asio::placeholders::bytes_transferred));
////		}
////		else {
////			std::cerr << "err (recv): " << err.message() << std::endl;
////		}
////	}
////
////private:
////	tcp::socket socket;
////	enum { max_length = 1024 };
////	char data[max_length];
////};
////
////class Server {
////public:
////	Server(boost::asio::io_service& ios,
////		short port) : ios(ios), acceptor(ios, tcp::endpoint(tcp::v4(), port))
////	{
////		do_accept();
////	}
////
////	void handle_accept(const boost::system::error_code& err, tcp::socket&& socket)
////	{
////		if (err) {
////			std::cerr << "err: " + err.message() << std::endl;
////			return;
////		}
////
////		//std::string remote_ip = socket.remote_endpoint().address().to_v6().to_string();
////		std::string remote_ip = socket.remote_endpoint().address().to_string();
////		std::make_shared<Session>(std::move(socket))->start();
////		do_accept();
////	}
////private:
////	void do_accept()
////	{
////		acceptor.async_accept(ios.get_executor(),
////			std::bind(&Server::handle_accept, this,
////				std::placeholders::_1,
////				std::placeholders::_2));
////	}
////private:
////	boost::asio::io_service& ios;
////	tcp::acceptor acceptor;
////};
////
////int main(int argc, char* argv[])
////{
////	try {
////		boost::asio::io_service ios;
////		Server s(ios, 8080);
////		ios.run();
////	}
////	catch (std::exception& e) {
////		std::cerr << e.what() << std::endl;
////	}
////	return 0;
////}
//
////#include <iostream>
////#include <boost/asio.hpp>
////#include <boost/beast/core.hpp>
////#include <boost/beast/http.hpp>
////#include <boost/beast/version.hpp>
////#include <boost/asio/post.hpp>
////#include <boost/asio/ip/tcp.hpp>
////#include <boost/asio/strand.hpp>
////#include <boost/asio/connect.hpp>
////#include <boost/beast/core.hpp>
////#include <boost/beast/ssl.hpp>
////#include <boost/beast/websocket.hpp>
////#include <boost/beast/websocket/ssl.hpp>
////#include <boost/asio/strand.hpp>
////#include <boost/asio/dispatch.hpp>
////#include <boost/beast/version.hpp>
////#include <boost/asio/spawn.hpp>
////#include <boost/asio/bind_executor.hpp>
////#include <boost/coroutine/asymmetric_coroutine.hpp>
////
////#include <boost/archive/iterators/base64_from_binary.hpp>
////#include <boost/archive/iterators/binary_from_base64.hpp>
////#include <boost/archive/iterators/transform_width.hpp>
////#include <boost/date_time/posix_time/posix_time.hpp>
////#include <boost/property_tree/json_parser.hpp>
////#include <boost/algorithm/string/regex.hpp>
////#include <boost/algorithm/string.hpp>
////#include <boost/property_tree/ptree.hpp>
////#include <boost/program_options.hpp>
////#include <boost/locale/encoding.hpp>
////#include <boost/lexical_cast.hpp>
////#include <boost/thread/mutex.hpp>
////#include <boost/foreach.hpp>
////#include <boost/regex.hpp>
////
////#include <boost/log/core.hpp>
////#include <boost/log/common.hpp>
////#include <boost/log/trivial.hpp>
////#include <boost/log/attributes.hpp>
////#include <boost/log/core/record.hpp>
////#include <boost/log/expressions.hpp>
////#include <boost/log/utility/setup.hpp>
////#include <boost/log/support/date_time.hpp>
////#include <boost/log/utility/setup/file.hpp>
////#include <boost/log/sinks/async_frontend.hpp>
////#include <boost/log/sinks/text_ostream_backend.hpp>
////#include <boost/log/utility/setup/common_attributes.hpp>
////#include <boost/log/utility/manipulators/add_value.hpp>
////#include <boost/filesystem.hpp>
////#include <boost/config.hpp>
////#include <boost/archive/text_oarchive.hpp>
////#include <boost/archive/text_iarchive.hpp>
////#include <boost/uuid/uuid.hpp>
////#include <boost/uuid/uuid_io.hpp>
////#include <boost/uuid/uuid_generators.hpp>
////
////
////namespace beast = boost::beast;         // from <boost/beast.hpp>
////namespace http = beast::http;           // from <boost/beast/http.hpp>
////namespace websocket = beast::websocket;         // from <boost/beast/websocket.hpp>
////namespace net = boost::asio;            // from <boost/asio.hpp>
////namespace bpo = boost::program_options;
////namespace ssl = boost::asio::ssl;               // from <boost/asio/ssl.hpp>
////using tcp = boost::asio::ip::tcp;
////using namespace boost::archive::iterators;
////
////bool Base64Encode(const std::string& input, std::string* output)
////{
////	typedef base64_from_binary<transform_width<std::string::const_iterator, 6, 8>> Base64EncodeIterator;
////	std::stringstream result;
////	try {
////		copy(Base64EncodeIterator(input.begin()), Base64EncodeIterator(input.end()), std::ostream_iterator<char>(result));
////	}
////	catch (...) {
////		return false;
////	}
////	size_t equal_count = (3 - input.length() % 3) % 3;
////	for (size_t i = 0; i < equal_count; i++)
////	{
////		result.put('=');
////	}
////	*output = result.str();
////	return output->empty() == false;
////}
////
////std::string get_timecheck(std::string userip)
////{
////	std::string newToken;
////	auto local_time = boost::posix_time::second_clock::local_time();
////	std::string strPosixTime = boost::posix_time::to_iso_string(local_time);
////	strPosixTime = strPosixTime.erase(strPosixTime.length() - 2, 2);
////	auto oldToken = userip+strPosixTime;
////	//auto oldToken = strPosixTime;
////	for (size_t i = 0; i < oldToken.size(); i++)
////		((char*)oldToken.c_str())[i] = oldToken.c_str()[i] ^ 0x38;
////	Base64Encode(oldToken, &newToken);
////	for (auto site = newToken.find("="); site != std::string::npos; site = newToken.find("=")) {
////		newToken = newToken.replace(site, 1, "");
////	}
////
////	return std::move(newToken);
////}
////
////bool Base64Decode(const std::string& input, std::string& output)
////{
////	typedef transform_width<binary_from_base64<std::string::const_iterator>, 8, 6> Base64DecodeIterator;
////	std::stringstream result;
////	try {
////		copy(Base64DecodeIterator(input.begin()), Base64DecodeIterator(input.end()), std::ostream_iterator<char>(result));
////	}
////	catch (...) {
////		return false;
////	}
////	
////	output = result.str();
////
////	for (size_t i = 0; i < output.size(); i++)
////		((char*)output.c_str())[i] = output.c_str()[i] ^ 0x38;
////
////	return output.empty() == false;
////}
////
////
////int main()
////{
////	std::string cookie1 = get_timecheck("127.0.0.1");
////	std::string de_cookie;
////	Base64Decode(cookie1,de_cookie);
////	std::vector<std::string>strs;
////	boost::split(strs, de_cookie, boost::is_any_of("127.0.0.1"));
////	auto current_local_time = boost::posix_time::second_clock::local_time();
////	auto last_local_time = boost::posix_time::from_iso_string(strs[1]);
////	auto tiemss = last_local_time - current_local_time;
////	std::cout << tiemss.total_seconds() << std::endl;
////	//std::string cookie2 = get_timecheck("127.0.0.1");
////
////	int i = 100;
////}
//
////#include <stddef.h>
////#include <stdio.h>
////#include <stdlib.h>
////#include <string.h>
////
////int myfunc(int i) {
////	*(int*)(NULL) = i; /* line 7 */
////	return i - 1;
////}
////
////int main(int argc, char** argv) {
////	/* Setup some memory. */
////	char data_ptr[] = "string in data segment";
////	char* mmap_ptr;
////	const char* text_ptr = "string in text segment";
////	(void)argv;
////	mmap_ptr = (char*)malloc(sizeof(data_ptr) + 1);
////	strcpy(mmap_ptr, data_ptr);
////	mmap_ptr[10] = 'm';
////	mmap_ptr[11] = 'm';
////	mmap_ptr[12] = 'a';
////	mmap_ptr[13] = 'p';
////	printf("text addr: %p\n", text_ptr);
////	printf("data addr: %p\n", data_ptr);
////	printf("mmap addr: %p\n", mmap_ptr);
////
////	/* Call a function to prepare a stack trace. */
////	return myfunc(argc);
////}
////
////#include<iostream>
////
////int main()
////{
////	int i = 0xFFEE;
////
////	unsigned char* ptr = (unsigned char*)&i;
////	
////	int value = (int)*ptr;
////	std::cout << value << std::endl;
////
////}
//
//
////
//// Copyright (c) 2016-2019 Vinnie Falco (vinnie dot falco at gmail dot com)
////
//// Distributed under the Boost Software License, Version 1.0. (See accompanying
//// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
////
//// Official repository: https://github.com/boostorg/beast
////
//
////------------------------------------------------------------------------------
////
//// Example: HTTP SSL server, asynchronous
////
////------------------------------------------------------------------------------
//
//////#include "example/common/server_certificate.hpp"
////
////#include <boost/beast/core.hpp>
////#include <boost/beast/http.hpp>
////#include <boost/beast/ssl.hpp>
////#include <boost/beast/version.hpp>
////#include <boost/asio/dispatch.hpp>
////#include <boost/asio/strand.hpp>
////#include <boost/config.hpp>
////#include <algorithm>
////#include <cstdlib>
////#include <functional>
////#include <iostream>
////#include <memory>
////#include <string>
////#include <thread>
////#include <vector>
////
////namespace beast = boost::beast;         // from <boost/beast.hpp>
////namespace http = beast::http;           // from <boost/beast/http.hpp>
////namespace net = boost::asio;            // from <boost/asio.hpp>
////namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
////using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
////
////// Return a reasonable mime type based on the extension of a file.
////beast::string_view
////mime_type(beast::string_view path)
////{
////	using beast::iequals;
////	auto const ext = [&path]
////	{
////		auto const pos = path.rfind(".");
////		if (pos == beast::string_view::npos)
////			return beast::string_view{};
////		return path.substr(pos);
////	}();
////	if (iequals(ext, ".htm"))  return "text/html";
////	if (iequals(ext, ".html")) return "text/html";
////	if (iequals(ext, ".php"))  return "text/html";
////	if (iequals(ext, ".css"))  return "text/css";
////	if (iequals(ext, ".txt"))  return "text/plain";
////	if (iequals(ext, ".js"))   return "application/javascript";
////	if (iequals(ext, ".json")) return "application/json";
////	if (iequals(ext, ".xml"))  return "application/xml";
////	if (iequals(ext, ".swf"))  return "application/x-shockwave-flash";
////	if (iequals(ext, ".flv"))  return "video/x-flv";
////	if (iequals(ext, ".png"))  return "image/png";
////	if (iequals(ext, ".jpe"))  return "image/jpeg";
////	if (iequals(ext, ".jpeg")) return "image/jpeg";
////	if (iequals(ext, ".jpg"))  return "image/jpeg";
////	if (iequals(ext, ".gif"))  return "image/gif";
////	if (iequals(ext, ".bmp"))  return "image/bmp";
////	if (iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
////	if (iequals(ext, ".tiff")) return "image/tiff";
////	if (iequals(ext, ".tif"))  return "image/tiff";
////	if (iequals(ext, ".svg"))  return "image/svg+xml";
////	if (iequals(ext, ".svgz")) return "image/svg+xml";
////	return "application/text";
////}
////
////// Append an HTTP rel-path to a local filesystem path.
////// The returned path is normalized for the platform.
////std::string
////path_cat(
////	beast::string_view base,
////	beast::string_view path)
////{
////	if (base.empty())
////		return std::string(path);
////	std::string result(base);
////#ifdef BOOST_MSVC
////	char constexpr path_separator = '\\';
////	if (result.back() == path_separator)
////		result.resize(result.size() - 1);
////	result.append(path.data(), path.size());
////	for (auto& c : result)
////		if (c == '/')
////			c = path_separator;
////#else
////	char constexpr path_separator = '/';
////	if (result.back() == path_separator)
////		result.resize(result.size() - 1);
////	result.append(path.data(), path.size());
////#endif
////	return result;
////}
////
////// This function produces an HTTP response for the given
////// request. The type of the response object depends on the
////// contents of the request, so the interface requires the
////// caller to pass a generic lambda for receiving the response.
////template<
////	class Body, class Allocator,
////	class Send>
////	void
////	handle_request(
////		beast::string_view doc_root,
////		http::request<Body, http::basic_fields<Allocator>>&& req,
////		Send&& send)
////{
////	// Returns a bad request response
////	auto const bad_request =
////		[&req](beast::string_view why)
////	{
////		http::response<http::string_body> res{ http::status::bad_request, req.version() };
////		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
////		res.set(http::field::content_type, "text/html");
////		res.keep_alive(req.keep_alive());
////		res.body() = std::string(why);
////		res.prepare_payload();
////		return res;
////	};
////
////	// Returns a not found response
////	auto const not_found =
////		[&req](beast::string_view target)
////	{
////		http::response<http::string_body> res{ http::status::not_found, req.version() };
////		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
////		res.set(http::field::content_type, "text/html");
////		res.keep_alive(req.keep_alive());
////		res.body() = "The resource '" + std::string(target) + "' was not found.";
////		res.prepare_payload();
////		return res;
////	};
////
////	// Returns a server error response
////	auto const server_error =
////		[&req](beast::string_view what)
////	{
////		http::response<http::string_body> res{ http::status::internal_server_error, req.version() };
////		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
////		res.set(http::field::content_type, "text/html");
////		res.keep_alive(req.keep_alive());
////		res.body() = "An error occurred: '" + std::string(what) + "'";
////		res.prepare_payload();
////		return res;
////	};
////
////	// Make sure we can handle the method
////	if (req.method() != http::verb::get &&
////		req.method() != http::verb::head)
////		return send(bad_request("Unknown HTTP-method"));
////
////	// Request path must be absolute and not contain "..".
////	if (req.target().empty() ||
////		req.target()[0] != '/' ||
////		req.target().find("..") != beast::string_view::npos)
////		return send(bad_request("Illegal request-target"));
////
////	// Build the path to the requested file
////	std::string path = path_cat(doc_root, req.target());
////	if (req.target().back() == '/')
////		path.append("index.html");
////
////	// Attempt to open the file
////	beast::error_code ec;
////	http::file_body::value_type body;
////	body.open(path.c_str(), beast::file_mode::scan, ec);
////
////	// Handle the case where the file doesn't exist
////	if (ec == beast::errc::no_such_file_or_directory)
////		return send(not_found(req.target()));
////
////	// Handle an unknown error
////	if (ec)
////		return send(server_error(ec.message()));
////
////	// Cache the size since we need it after the move
////	auto const size = body.size();
////
////	// Respond to HEAD request
////	if (req.method() == http::verb::head)
////	{
////		http::response<http::empty_body> res{ http::status::ok, req.version() };
////		res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
////		res.set(http::field::content_type, mime_type(path));
////		res.content_length(size);
////		res.keep_alive(req.keep_alive());
////		return send(std::move(res));
////	}
////
////	// Respond to GET request
////	http::response<http::file_body> res{
////		std::piecewise_construct,
////		std::make_tuple(std::move(body)),
////		std::make_tuple(http::status::ok, req.version()) };
////	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
////	res.set(http::field::content_type, mime_type(path));
////	res.content_length(size);
////	res.keep_alive(req.keep_alive());
////	return send(std::move(res));
////}
////
//////------------------------------------------------------------------------------
////
////// Report a failure
////void
////fail(beast::error_code ec, char const* what)
////{
////	// ssl::error::stream_truncated, also known as an SSL "short read",
////	// indicates the peer closed the connection without performing the
////	// required closing handshake (for example, Google does this to
////	// improve performance). Generally this can be a security issue,
////	// but if your communication protocol is self-terminated (as
////	// it is with both HTTP and WebSocket) then you may simply
////	// ignore the lack of close_notify.
////	//
////	// https://github.com/boostorg/beast/issues/38
////	//
////	// https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
////	//
////	// When a short read would cut off the end of an HTTP message,
////	// Beast returns the error beast::http::error::partial_message.
////	// Therefore, if we see a short read here, it has occurred
////	// after the message has been completed, so it is safe to ignore it.
////
////	if (ec == net::ssl::error::stream_truncated)
////		return;
////
////	std::cerr << what << ": " << ec.message() << "\n";
////}
////
////// Handles an HTTP server connection
////class session1 : public std::enable_shared_from_this<session1>
////{
////	// This is the C++11 equivalent of a generic lambda.
////	// The function object is used to send an HTTP message.
////	struct send_lambda
////	{
////		session1& self_;
////
////		explicit
////			send_lambda(session1& self)
////			: self_(self)
////		{
////		}
////
////		template<bool isRequest, class Body, class Fields>
////		void
////			operator()(http::message<isRequest, Body, Fields>&& msg) const
////		{
////			// The lifetime of the message has to extend
////			// for the duration of the async operation so
////			// we use a shared_ptr to manage it.
////			auto sp = std::make_shared<
////				http::message<isRequest, Body, Fields>>(std::move(msg));
////
////			// Store a type-erased version of the shared
////			// pointer in the class to keep it alive.
////			self_.res_ = sp;
////
////			// Write the response
////			http::async_write(
////				self_.stream_,
////				*sp,
////				beast::bind_front_handler(
////					&session1::on_write,
////					self_.shared_from_this(),
////					sp->need_eof()));
////		}
////	};
////
////	beast::ssl_stream<beast::tcp_stream> stream_;
////	beast::flat_buffer buffer_;
////	std::shared_ptr<std::string const> doc_root_;
////	http::request<http::string_body> req_;
////	std::shared_ptr<void> res_;
////	send_lambda lambda_;
////
////public:
////	// Take ownership of the socket
////	explicit
////		session1(
////			tcp::socket&& socket,
////			ssl::context& ctx,
////			std::shared_ptr<std::string const> const& doc_root)
////		: stream_(std::move(socket), ctx)
////		, doc_root_(doc_root)
////		, lambda_(*this)
////	{
////	}
////
////	// Start the asynchronous operation
////	void
////		run()
////	{
////		// We need to be executing within a strand to perform async operations
////		// on the I/O objects in this session. Although not strictly necessary
////		// for single-threaded contexts, this example code is written to be
////		// thread-safe by default.
////		net::dispatch(
////			stream_.get_executor(),
////			beast::bind_front_handler(
////				&session1::on_run,
////				shared_from_this()));
////	}
////
////	void
////		on_run()
////	{
////		// Set the timeout.
////		beast::get_lowest_layer(stream_).expires_after(
////			std::chrono::seconds(30));
////
////		// Perform the SSL handshake
////		stream_.async_handshake(
////			ssl::stream_base::server,
////			beast::bind_front_handler(
////				&session1::on_handshake,
////				shared_from_this()));
////	}
////
////	void
////		on_handshake(beast::error_code ec)
////	{
////		if (ec)
////			return fail(ec, "handshake");
////
////		do_read();
////	}
////
////	void
////		do_read()
////	{
////		// Make the request empty before reading,
////		// otherwise the operation behavior is undefined.
////		req_ = {};
////
////		// Set the timeout.
////		beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
////
////		// Read a request
////		http::async_read(stream_, buffer_, req_,
////			beast::bind_front_handler(
////				&session1::on_read,
////				shared_from_this()));
////	}
////
////	void
////		on_read(
////			beast::error_code ec,
////			std::size_t bytes_transferred)
////	{
////		boost::ignore_unused(bytes_transferred);
////
////		// This means they closed the connection
////		if (ec == http::error::end_of_stream)
////			return do_close();
////
////		if (ec)
////			return fail(ec, "read");
////
////		// Send the response
////		handle_request(*doc_root_, std::move(req_), lambda_);
////	}
////
////	void
////		on_write(
////			bool close,
////			beast::error_code ec,
////			std::size_t bytes_transferred)
////	{
////		boost::ignore_unused(bytes_transferred);
////
////		if (ec)
////			return fail(ec, "write");
////
////		if (close)
////		{
////			// This means we should close the connection, usually because
////			// the response indicated the "Connection: close" semantic.
////			return do_close();
////		}
////
////		// We're done with the response so delete it
////		res_ = nullptr;
////
////		// Read another request
////		do_read();
////	}
////
////	void
////		do_close()
////	{
////		// Set the timeout.
////		beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
////
////		// Perform the SSL shutdown
////		stream_.async_shutdown(
////			beast::bind_front_handler(
////				&session1::on_shutdown,
////				shared_from_this()));
////	}
////
////	void
////		on_shutdown(beast::error_code ec)
////	{
////		if (ec)
////			return fail(ec, "shutdown");
////
////		// At this point the connection is closed gracefully
////	}
////};
////
//////------------------------------------------------------------------------------
////
////// Accepts incoming connections and launches the sessions
////class listener1 : public std::enable_shared_from_this<listener1>
////{
////	net::io_context& ioc_;
////	ssl::context& ctx_;
////	tcp::acceptor acceptor_;
////	std::shared_ptr<std::string const> doc_root_;
////
////public:
////	listener1(
////		net::io_context& ioc,
////		ssl::context& ctx,
////		tcp::endpoint endpoint,
////		std::shared_ptr<std::string const> const& doc_root)
////		: ioc_(ioc)
////		, ctx_(ctx)
////		, acceptor_(ioc)
////		, doc_root_(doc_root)
////	{
////		beast::error_code ec;
////
////		// Open the acceptor
////		acceptor_.open(endpoint.protocol(), ec);
////		if (ec)
////		{
////			fail(ec, "open");
////			return;
////		}
////
////		// Allow address reuse
////		acceptor_.set_option(net::socket_base::reuse_address(true), ec);
////		if (ec)
////		{
////			fail(ec, "set_option");
////			return;
////		}
////
////		// Bind to the server address
////		acceptor_.bind(endpoint, ec);
////		if (ec)
////		{
////			fail(ec, "bind");
////			return;
////		}
////
////		// Start listening for connections
////		acceptor_.listen(
////			net::socket_base::max_listen_connections, ec);
////		if (ec)
////		{
////			fail(ec, "listen");
////			return;
////		}
////	}
////
////	// Start accepting incoming connections
////	void
////		run()
////	{
////		do_accept();
////	}
////
////private:
////	void
////		do_accept()
////	{
////		// The new connection gets its own strand
////		acceptor_.async_accept(
////			net::make_strand(ioc_),
////			beast::bind_front_handler(
////				&listener1::on_accept,
////				shared_from_this()));
////	}
////
////	void
////		on_accept(beast::error_code ec, tcp::socket socket)
////	{
////		if (ec)
////		{
////			fail(ec, "accept");
////		}
////		else
////		{
////			// Create the session and run it
////			std::make_shared<session1>(
////				std::move(socket),
////				ctx_,
////				doc_root_)->run();
////		}
////
////		// Accept another connection
////		do_accept();
////	}
////};
////
//////------------------------------------------------------------------------------
////
////struct ssl_configure {
////	std::string cert_file;          //private cert
////	std::string key_file;           //private key
////	std::string passp_hrase;        //password;//私有key，是否输入密码
////	std::string pem_flie;           //*.pem文件
////};
////
////int main(int argc, char* argv[])
////{
////
////	auto const address = net::ip::make_address("0.0.0.0");
////	auto const port = static_cast<unsigned short>(std::atoi("8080"));
////	auto const doc_root = std::make_shared<std::string>("/");
////	auto const threads = 1;
////
////	// The io_context is required for all I/O
////	net::io_context ioc{ threads };
////
////	unsigned long ssl_options = boost::asio::ssl::context::default_workarounds
////		| boost::asio::ssl::context::no_sslv3
////		| boost::asio::ssl::context::no_sslv2
////		| boost::asio::ssl::context::single_dh_use;
////	// The SSL context is required, and holds certificates
////	ssl::context ctx{ ssl::context::tlsv12 };
////
////	ssl_configure ssl_conf{ "./3582168__job-sky.com_public.crt","./3582168__job-sky.com.key" };
////
////	//boost::asio::ssl::context ssl_context(boost::asio::ssl::context::tlsv13);//tsl1.3
////	//boost::asio::ssl::context ssl_context(boost::asio::ssl::context::sslv23);
////	ctx.set_options(ssl_options);
////
////	ctx.use_certificate_chain_file(std::move(ssl_conf.cert_file));
////
////	ctx.use_private_key_file(std::move(ssl_conf.key_file), boost::asio::ssl::context::pem);
////
////	// This holds the self-signed certificate used by the server
////	//load_server_certificate(ctx);
////
////	// Create and launch a listening port
////	std::make_shared<listener1>(
////		ioc,
////		ctx,
////		tcp::endpoint{ address, port },
////		doc_root)->run();
////
////	// Run the I/O service on the requested number of threads
////	std::vector<std::thread> v;
////	v.reserve(threads - 1);
////	for (auto i = threads - 1; i > 0; --i)
////		v.emplace_back(
////			[&ioc]
////			{
////				ioc.run();
////			});
////	ioc.run();
////
////	return EXIT_SUCCESS;
////}
//
////#include <cstdlib>
////#include <cstring>
////#include <functional>
////#include <iostream>
////#include <boost/asio.hpp>
////#include <boost/asio/ssl.hpp>
////
////#ifdef _DEBUG
////#pragma comment(lib, "crypt32")
////#pragma comment(lib, "libssl64MTd.lib")
////#pragma comment(lib, "libcrypto64MTd.lib")
////#else
////#pragma comment(lib, "crypt32")
////#pragma comment(lib, "libssl64MT.lib")
////#pragma comment(lib, "libcrypto64MT.lib")
////
////#endif
////
////using boost::asio::ip::tcp;
////using std::placeholders::_1;
////using std::placeholders::_2;
////
////enum { max_length = 1024 };
////
////static const std::string g_cert_pem =
////"-----BEGIN CERTIFICATE-----\n"
////"MIIFqDCCBJCgAwIBAgIQBB6xHeishzP2PUJFiEmKcTANBgkqhkiG9w0BAQsFADBe\n"
////"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
////"d3cuZGlnaWNlcnQuY29tMR0wGwYDVQQDExRSYXBpZFNTTCBSU0EgQ0EgMjAxODAe\n"
////"Fw0yMDAzMTEwMDAwMDBaFw0yMTAzMTExMjAwMDBaMBQxEjAQBgNVBAMMCSoudXBr\n"
////"Lm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMaPe+e8kH5gprri\n"
////"7uCN+TLUACD7c7d1+Ur3RNcgq+j3IgfXkcAGSeVxrEQj6esKkIe2QBlUp22lhKrU\n"
////"rttbt6LnFp6n9u4gzpELqFtEBOShIdCbiuJYLaO8Dt/db1be9u/leJkannDdBzXu\n"
////"wyhSGnvJSSEVwbr3xN62gDwmuGi+uO+Bvo8q8D9vk4WgH6xMCk7GB++BULfClWgG\n"
////"wDv/m7uicdwfCE0y8QDxK4P0yZRglk8UubizHRUN0E5Q2cGKdckWUCsRopQoSVBl\n"
////"v6vzm3Uk5bqGL4/CDY7CYE9HJIGvgfOZgtSI99igrvsueWds+x2G5/5X7oejkEM5\n"
////"h9SoTZECAwEAAaOCAqowggKmMB8GA1UdIwQYMBaAFFPKF1n8a8ADIS8aruSqqByC\n"
////"Vtp1MB0GA1UdDgQWBBRtzVU13eusG6Epih57skwhsW0leTAdBgNVHREEFjAUggkq\n"
////"LnVway5uZXSCB3Vway5uZXQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\n"
////"AQUFBwMBBggrBgEFBQcDAjA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vY2RwLnJh\n"
////"cGlkc3NsLmNvbS9SYXBpZFNTTFJTQUNBMjAxOC5jcmwwTAYDVR0gBEUwQzA3Bglg\n"
////"hkgBhv1sAQIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29t\n"
////"L0NQUzAIBgZngQwBAgEwdQYIKwYBBQUHAQEEaTBnMCYGCCsGAQUFBzABhhpodHRw\n"
////"Oi8vc3RhdHVzLnJhcGlkc3NsLmNvbTA9BggrBgEFBQcwAoYxaHR0cDovL2NhY2Vy\n"
////"dHMucmFwaWRzc2wuY29tL1JhcGlkU1NMUlNBQ0EyMDE4LmNydDAJBgNVHRMEAjAA\n"
////"MIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYApLkJkLQYWBSHuxOizGdwCjw1mAT5\n"
////"G9+443fNDsgN3BAAAAFwyRUzeQAABAMARzBFAiAf5V/Q1s+uCeNx2ZLdd2kQ7c5I\n"
////"Ig8fL3NFANy6pmUZPwIhAJxiTWVpHAaw6vfqUMIc2yWeAIsD1RCybpWvp+Kzo4AZ\n"
////"AHYAXNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDsoAAAFwyRUzvgAABAMA\n"
////"RzBFAiAvQpmLtTUoM+8ApI0wxf/jKKOPtY2A6E9BR2CqTtUwFgIhAJv/58T64Lj6\n"
////"2m06o6zbUaZsNicBQulwg5FTfPUlDPT1MA0GCSqGSIb3DQEBCwUAA4IBAQASjfTh\n"
////"2c8bMmZlPx9OBDyTuOK5BfEHhguFBV4Qhv4MXsRMPZQk7eN+3XV/9KSYXwz67EvB\n"
////"wQR4JeG0SHrlHfLIDqwMj0yekPwovPbMGgz3crwiwggPkA3r3xhMiaGWYwYd5ppP\n"
////"t1xZP9DhGqRWaX60MiIQ50RT1lGpEUjyqN3GpDSF/bc16JBgAHz9sjH6JdW/cLou\n"
////"R+gRRbzuln/Exlq/iHQpjd/BMfgeTZJRKjNN4nQ3Pj6VfuBpTO81qa/bA4gFehFW\n"
////"3yIkg/KlkHGoEblBzybwyghemB476HtcjQqetMWznDu7DkC9HgRRoK7G1l3CcgyY\n"
////"A1wt7MQ/TMWODKz3\n"
////"-----END CERTIFICATE-----";
////
////static const std::string g_cert_key =
////"-----BEGIN RSA PRIVATE KEY-----\n"
////"MIIEowIBAAKCAQEAxo9757yQfmCmuuLu4I35MtQAIPtzt3X5SvdE1yCr6PciB9eR\n"
////"wAZJ5XGsRCPp6wqQh7ZAGVSnbaWEqtSu21u3oucWnqf27iDOkQuoW0QE5KEh0JuK\n"
////"4lgto7wO391vVt727+V4mRqecN0HNe7DKFIae8lJIRXBuvfE3raAPCa4aL6474G+\n"
////"jyrwP2+ThaAfrEwKTsYH74FQt8KVaAbAO/+bu6Jx3B8ITTLxAPErg/TJlGCWTxS5\n"
////"uLMdFQ3QTlDZwYp1yRZQKxGilChJUGW/q/ObdSTluoYvj8INjsJgT0ckga+B85mC\n"
////"1Ij32KCu+y55Z2z7HYbn/lfuh6OQQzmH1KhNkQIDAQABAoIBAQCe+tlRVVg357j3\n"
////"X6W1o9cIDFhCEDK5jLrafBrhSGZ8dAsKTl6DakWWcSplsH+lUmMgVhsCbRZVIzaS\n"
////"9RE/zzK8OtyQkZmTVi8uUTAuSsrEKAOEHFXaHpIETBl4wrpXytPahlfF9lsvsLkK\n"
////"RK57RSmxPRvRYrMnuSQm0ebgwnvaWJiQ2tslCEkZ9Ppl/a4/BJJ2VQF+Sx1O8bLi\n"
////"FDbS9LJjbXwk5QSF9DBPgzudMTNmaGNlZ/yo/ZEsmL6k2d3ShvK/MLYpkMnMfoPC\n"
////"WDboJqf8eMkeSOvdmB6PA9Ub1uy/pFD0p9ln4/XBxQsS3Ftu8mdT+A5SOINGZzdY\n"
////"LgNoAcVxAoGBAPI3pSX8D0ZVabFH3N22fnPvrZsLV7jtaNPhGTxapZbeDhEbNvAG\n"
////"BQP4zwjLt0ZQ142FnJZZAgTzsAz7bvNYB/At5/hl5v8z3UKfLWrw3RvXUO1+ulP+\n"
////"mibFP/ZQVbFqG8NcIgTkNI9sKxlmp8Zbp4oz/XZlCheWot24QmA5mTPVAoGBANHb\n"
////"5MrOaBQBUsF04IOZg3uDwu1P0pkQQKkotvoFpEkoL29TCZrGDSeGIgNWe1et7lYr\n"
////"Roz+LNs2zvyWR3dmefacXoNu5ZGTyAWmHwJhp1ivEgiZ7P46R+tvlpT9Ew+aVzEp\n"
////"xmjUdfcfP/9XUh7GpBCFn8bqi4OC3RqKRps51JzNAoGAbmkzHNeDVvpETY2GfoJb\n"
////"rhmJN226NQ/zgvHPARYI+XaLTvzq1ArKan8WUNob1y+uslI/iMFWDE/Q5noOn1p3\n"
////"c+JZJX++BoLrzxykJWVaRQCnYTstUHB0cEvl1i/UgCTwNuNeloA3/VC/bLrAq8jH\n"
////"3FXKqhdwvEPsRcliaF6ZGWkCgYAfq1FxkYh/TFvSufKPqYEACLhH273qP1uiq3RB\n"
////"csyCBcByylMuuiiOCF3lpw1iA+ttsYYqDMl0I2dFEuCiEiLhpmNU7k1SlLygrZsM\n"
////"XvREG9da2O+8xcrIqsRMo4xW1HHIB4fblgRfUKX1wJWx80QbAi9Ec2yuYfc/5BIX\n"
////"priBGQKBgCQpr65vbO/i58h+3rBpYaBmLwJ6Lr51eCTSo2RyFPAH9wRy+c0S4Pka\n"
////"ocfJafR7BRZn9mK8SrTW+i6HjioO7DdZ/KgZwMMxFxq57/h8ZYT+Ni7YeepXd5tg\n"
////"yrTWdxDsTvzx/ij3HRWwwkHo8XjMO4rohat3JMjp7o+c2vZ9ONv6\n"
////"-----END RSA PRIVATE KEY-----";
////class client
////{
////public:
////    client(boost::asio::io_context& io_context,
////        boost::asio::ssl::context& context,
////        const tcp::resolver::results_type& endpoints)
////        : socket_(io_context, context)
////    {
////        socket_.set_verify_mode(boost::asio::ssl::verify_peer);
////        socket_.set_verify_callback(
////            std::bind(&client::verify_certificate, this,std::placeholders::_1, std::placeholders::_2));
////
////		if (!SSL_set_tlsext_host_name(socket_.native_handle(), "caonima.upk.net")) {
////			return;
////		}
////        connect(endpoints);
////    }
////
////private:
////    bool verify_certificate(bool preverified,
////        boost::asio::ssl::verify_context& ctx)
////    {
////        // The verify callback can be used to check whether the certificate that is
////        // being presented is valid for the peer. For example, RFC 2818 describes
////        // the steps involved in doing this for HTTPS. Consult the OpenSSL
////        // documentation for more details. Note that the callback is called once
////        // for each certificate in the certificate chain, starting from the root
////        // certificate authority.
////
////        // In this example we will simply print the certificate's subject name.
////        char subject_name[256];
////        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
////        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
////        std::cout << "Verifying " << subject_name << "\n";
////        return preverified;
////    }
////
////    void connect(const tcp::resolver::results_type& endpoints)
////    {
////        boost::asio::async_connect(socket_.lowest_layer(), endpoints,
////            [this](const boost::system::error_code& error,
////                const tcp::endpoint& /*endpoint*/)
////            {
////                if (!error)
////                {
////                    handshake();
////                }
////                else
////                {
////                    std::cout << "Connect failed: " << error.message() << "\n";
////                }
////            });
////    }
////
////    void handshake()
////    {
////        socket_.async_handshake(boost::asio::ssl::stream_base::client,
////            [this](const boost::system::error_code& error)
////            {
////                if (!error)
////                {
////                    send_request();
////                }
////                else
////                {
////                    std::cout << "Handshake failed: " << error.message() << "\n";
////                }
////            });
////    }
////
////    void send_request()
////    {
////        std::cout << "Enter message: ";
////        std::cin.getline(request_, max_length);
////        size_t request_length = std::strlen(request_);
////
////        boost::asio::async_write(socket_,
////            boost::asio::buffer(request_, request_length),
////            [this](const boost::system::error_code& error, std::size_t length)
////            {
////                if (!error)
////                {
////                    receive_response(length);
////                }
////                else
////                {
////                    std::cout << "Write failed: " << error.message() << "\n";
////                }
////            });
////    }
////
////    void receive_response(std::size_t length)
////    {
////        boost::asio::async_read(socket_,
////            boost::asio::buffer(reply_, length),
////            [this](const boost::system::error_code& error, std::size_t length)
////            {
////                if (!error)
////                {
////                    std::cout << "Reply: ";
////                    std::cout.write(reply_, length);
////                    std::cout << "\n";
////                }
////                else
////                {
////                    std::cout << "Read failed: " << error.message() << "\n";
////                }
////            });
////    }
////
////    boost::asio::ssl::stream<tcp::socket> socket_;
////    char request_[max_length];
////    char reply_[max_length];
////};
////
////int main()
////{
////	const std::string DEFAULT_CIPHERS = (
////		"ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:"
////		"ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:"
////		"!aNULL:!eNULL:!MD5:!3DES"
////		"HIGH:!DH:!aNULL"
////		);
////
////    try
////    {
////        boost::asio::io_context io_context;
////
////        tcp::resolver resolver(io_context);
////        auto endpoints = resolver.resolve("wsmw.hehehee.com","9777");
////
////        boost::asio::ssl::context ctx(boost::asio::ssl::context::tls);
////       
////		ctx.set_verify_mode( boost::asio::ssl::verify_peer| boost::asio::ssl::verify_fail_if_no_peer_cert);
////        //ctx.load_verify_file("ca.pem");
////		boost::system::error_code ec;
////        ctx.add_certificate_authority(
////			boost::asio::buffer(g_cert_pem.data(), g_cert_pem.size()), ec);
////
////        client c(io_context, ctx, endpoints);
////
////        io_context.run();
////    }
////    catch (std::exception& e)
////    {
////        std::cerr << "Exception: " << e.what() << "\n";
////    }
////
////    return 0;
////}
//
////
////#include <boost/beast/core.hpp>
////#include <boost/beast/http.hpp>
////#include <boost/beast/ssl.hpp>
////#include <boost/beast/version.hpp>
////#include <boost/asio/dispatch.hpp>
////#include <boost/asio/strand.hpp>
////#include <boost/config.hpp>
////#include <algorithm>
////#include <cstdlib>
////#include <functional>
////#include <iostream>
////#include <memory>
////#include <string>
////#include <thread>
////#include <vector>
////
////#ifdef _DEBUG
////#pragma comment(lib, "crypt32")
////#pragma comment(lib, "libssl64MTd.lib")
////#pragma comment(lib, "libcrypto64MTd.lib")
////#else
////#pragma comment(lib, "crypt32")
////#pragma comment(lib, "libssl64MT.lib")
////#pragma comment(lib, "libcrypto64MT.lib")
////#endif
////
////namespace beast = boost::beast;         // from <boost/beast.hpp>
////namespace http = beast::http;           // from <boost/beast/http.hpp>
////namespace net = boost::asio;            // from <boost/asio.hpp>
////namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
////using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
////
////// Return a reasonable mime type based on the extension of a file.
////beast::string_view
////mime_type(beast::string_view path)
////{
////	using beast::iequals;
////	auto const ext = [&path]
////	{
////		auto const pos = path.rfind(".");
////		if (pos == beast::string_view::npos)
////			return beast::string_view{};
////		return path.substr(pos);
////	}();
////	if (iequals(ext, ".htm"))  return "text/html";
////	if (iequals(ext, ".html")) return "text/html";
////	if (iequals(ext, ".php"))  return "text/html";
////	if (iequals(ext, ".css"))  return "text/css";
////	if (iequals(ext, ".txt"))  return "text/plain";
////	if (iequals(ext, ".js"))   return "application/javascript";
////	if (iequals(ext, ".json")) return "application/json";
////	if (iequals(ext, ".xml"))  return "application/xml";
////	if (iequals(ext, ".swf"))  return "application/x-shockwave-flash";
////	if (iequals(ext, ".flv"))  return "video/x-flv";
////	if (iequals(ext, ".png"))  return "image/png";
////	if (iequals(ext, ".jpe"))  return "image/jpeg";
////	if (iequals(ext, ".jpeg")) return "image/jpeg";
////	if (iequals(ext, ".jpg"))  return "image/jpeg";
////	if (iequals(ext, ".gif"))  return "image/gif";
////	if (iequals(ext, ".bmp"))  return "image/bmp";
////	if (iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
////	if (iequals(ext, ".tiff")) return "image/tiff";
////	if (iequals(ext, ".tif"))  return "image/tiff";
////	if (iequals(ext, ".svg"))  return "image/svg+xml";
////	if (iequals(ext, ".svgz")) return "image/svg+xml";
////	return "application/text";
////}
////
////// Append an HTTP rel-path to a local filesystem path.
////// The returned path is normalized for the platform.
////std::string
////path_cat(
////	beast::string_view base,
////	beast::string_view path)
////{
////	if (base.empty())
////		return std::string(path);
////	std::string result(base);
////#ifdef BOOST_MSVC
////	char constexpr path_separator = '\\';
////	if (result.back() == path_separator)
////		result.resize(result.size() - 1);
////	result.append(path.data(), path.size());
////	for (auto& c : result)
////		if (c == '/')
////			c = path_separator;
////#else
////	char constexpr path_separator = '/';
////	if (result.back() == path_separator)
////		result.resize(result.size() - 1);
////	result.append(path.data(), path.size());
////#endif
////	return result;
////}
////
////// This function produces an HTTP response for the given
////// request. The type of the response object depends on the
////// contents of the request, so the interface requires the
////// caller to pass a generic lambda for receiving the response.
////template<
////	class Body, class Allocator,
////	class Send>
////	void
////	handle_request(
////		beast::string_view doc_root,
////		http::request<Body, http::basic_fields<Allocator>>&& req,
////		Send&& send)
////{
////
////	std::string body_str = "hello world";
////
////	// Cache the size since we need it after the move
////	auto const size = body_str.size();
////
////	// Respond to GET request
////	http::response<http::string_body> res;
////	res.body() = body_str;
////	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
////	res.set(http::field::content_type, "text/plain");
////	res.content_length(size);
////	res.prepare_payload();
////	return send(std::move(res));
////}
////
//////------------------------------------------------------------------------------
////
////// Report a failure
////void
////fail(beast::error_code ec, char const* what)
////{
////	// ssl::error::stream_truncated, also known as an SSL "short read",
////	// indicates the peer closed the connection without performing the
////	// required closing handshake (for example, Google does this to
////	// improve performance). Generally this can be a security issue,
////	// but if your communication protocol is self-terminated (as
////	// it is with both HTTP and WebSocket) then you may simply
////	// ignore the lack of close_notify.
////	//
////	// https://github.com/boostorg/beast/issues/38
////	//
////	// https://security.stackexchange.com/questions/91435/how-to-handle-a-malicious-ssl-tls-shutdown
////	//
////	// When a short read would cut off the end of an HTTP message,
////	// Beast returns the error beast::http::error::partial_message.
////	// Therefore, if we see a short read here, it has occurred
////	// after the message has been completed, so it is safe to ignore it.
////
////	if (ec == net::ssl::error::stream_truncated)
////		return;
////
////	std::cerr << what << ": " << ec.message() << "\n";
////}
////
////// Handles an HTTP server connection
////class session : public std::enable_shared_from_this<session>
////{
////	// This is the C++11 equivalent of a generic lambda.
////	// The function object is used to send an HTTP message.
////	struct send_lambda
////	{
////		session& self_;
////
////		explicit
////			send_lambda(session& self)
////			: self_(self)
////		{
////		}
////
////		template<bool isRequest, class Body, class Fields>
////		void
////			operator()(http::message<isRequest, Body, Fields>&& msg) const
////		{
////			// The lifetime of the message has to extend
////			// for the duration of the async operation so
////			// we use a shared_ptr to manage it.
////			auto sp = std::make_shared<
////				http::message<isRequest, Body, Fields>>(std::move(msg));
////
////			// Store a type-erased version of the shared
////			// pointer in the class to keep it alive.
////			self_.res_ = sp;
////
////			// Write the response
////			http::async_write(
////				self_.stream_,
////				*sp,
////				beast::bind_front_handler(
////					&session::on_write,
////					self_.shared_from_this(),
////					sp->need_eof()));
////		}
////	};
////
////	beast::ssl_stream<beast::tcp_stream> stream_;
////	beast::flat_buffer buffer_;
////	std::shared_ptr<std::string const> doc_root_;
////	http::request<http::string_body> req_;
////	std::shared_ptr<void> res_;
////	send_lambda lambda_;
////
////public:
////	// Take ownership of the socket
////	explicit
////		session(
////			tcp::socket&& socket,
////			ssl::context& ctx,
////			std::shared_ptr<std::string const> const& doc_root)
////		: stream_(std::move(socket), ctx)
////		, doc_root_(doc_root)
////		, lambda_(*this)
////	{
////	}
////
////	// Start the asynchronous operation
////	void
////		run()
////	{
////		// We need to be executing within a strand to perform async operations
////		// on the I/O objects in this session. Although not strictly necessary
////		// for single-threaded contexts, this example code is written to be
////		// thread-safe by default.
////		net::dispatch(
////			stream_.get_executor(),
////			beast::bind_front_handler(
////				&session::on_run,
////				shared_from_this()));
////	}
////
////	void
////		on_run()
////	{
////		// Set the timeout.
////		beast::get_lowest_layer(stream_).expires_after(
////			std::chrono::seconds(30));
////
////		// Perform the SSL handshake
////		stream_.async_handshake(
////			ssl::stream_base::server,
////			beast::bind_front_handler(
////				&session::on_handshake,
////				shared_from_this()));
////	}
////
////	void
////		on_handshake(beast::error_code ec)
////	{
////		if (ec)
////			return fail(ec, "handshake");
////
////		do_read();
////	}
////
////	void
////		do_read()
////	{
////		// Make the request empty before reading,
////		// otherwise the operation behavior is undefined.
////		req_ = {};
////
////		// Set the timeout.
////		beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
////
////		// Read a request
////		http::async_read(stream_, buffer_, req_,
////			beast::bind_front_handler(
////				&session::on_read,
////				shared_from_this()));
////	}
////
////	void
////		on_read(
////			beast::error_code ec,
////			std::size_t bytes_transferred)
////	{
////		boost::ignore_unused(bytes_transferred);
////
////		// This means they closed the connection
////		if (ec == http::error::end_of_stream)
////			return do_close();
////
////		if (ec)
////			return fail(ec, "read");
////
////		// Send the response
////		handle_request(*doc_root_, std::move(req_), lambda_);
////	}
////
////	void
////		on_write(
////			bool close,
////			beast::error_code ec,
////			std::size_t bytes_transferred)
////	{
////		boost::ignore_unused(bytes_transferred);
////
////		if (ec)
////			return fail(ec, "write");
////
////		if (close)
////		{
////			// This means we should close the connection, usually because
////			// the response indicated the "Connection: close" semantic.
////			return do_close();
////		}
////
////		// We're done with the response so delete it
////		res_ = nullptr;
////
////		// Read another request
////		do_read();
////	}
////
////	void
////		do_close()
////	{
////		// Set the timeout.
////		beast::get_lowest_layer(stream_).expires_after(std::chrono::seconds(30));
////
////		// Perform the SSL shutdown
////		stream_.async_shutdown(
////			beast::bind_front_handler(
////				&session::on_shutdown,
////				shared_from_this()));
////	}
////
////	void
////		on_shutdown(beast::error_code ec)
////	{
////		if (ec)
////			return fail(ec, "shutdown");
////
////		// At this point the connection is closed gracefully
////	}
////};
////
//////------------------------------------------------------------------------------
////
////// Accepts incoming connections and launches the sessions
////class listener : public std::enable_shared_from_this<listener>
////{
////	net::io_context& ioc_;
////	ssl::context& ctx_;
////	tcp::acceptor acceptor_;
////	std::shared_ptr<std::string const> doc_root_;
////
////public:
////	listener(
////		net::io_context& ioc,
////		ssl::context& ctx,
////		tcp::endpoint endpoint,
////		std::shared_ptr<std::string const> const& doc_root)
////		: ioc_(ioc)
////		, ctx_(ctx)
////		, acceptor_(ioc)
////		, doc_root_(doc_root)
////	{
////		beast::error_code ec;
////
////		// Open the acceptor
////		acceptor_.open(endpoint.protocol(), ec);
////		if (ec)
////		{
////			fail(ec, "open");
////			return;
////		}
////
////		// Allow address reuse
////		acceptor_.set_option(net::socket_base::reuse_address(true), ec);
////		if (ec)
////		{
////			fail(ec, "set_option");
////			return;
////		}
////
////		// Bind to the server address
////		acceptor_.bind(endpoint, ec);
////		if (ec)
////		{
////			fail(ec, "bind");
////			return;
////		}
////
////		// Start listening for connections
////		acceptor_.listen(
////			net::socket_base::max_listen_connections, ec);
////		if (ec)
////		{
////			fail(ec, "listen");
////			return;
////		}
////	}
////
////	// Start accepting incoming connections
////	void
////		run()
////	{
////		do_accept();
////	}
////
////private:
////	void
////		do_accept()
////	{
////		// The new connection gets its own strand
////		acceptor_.async_accept(
////			net::make_strand(ioc_),
////			beast::bind_front_handler(
////				&listener::on_accept,
////				shared_from_this()));
////	}
////
////	void
////		on_accept(beast::error_code ec, tcp::socket socket)
////	{
////		if (ec)
////		{
////			fail(ec, "accept");
////		}
////		else
////		{
////			// Create the session and run it
////			std::make_shared<session>(
////				std::move(socket),
////				ctx_,
////				doc_root_)->run();
////		}
////
////		// Accept another connection
////		do_accept();
////	}
////};
////
//////------------------------------------------------------------------------------
////
////
////void
////load_server_certificate(boost::asio::ssl::context& ctx)
////{
////	/*
////	The certificate was generated from CMD.EXE on Windows 10 using:
////
////	winpty openssl dhparam -out dh.pem 2048
////	winpty openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 10000 -out cert.pem -subj "//C=US\ST=CA\L=Los Angeles\O=Beast\CN=www.example.com"
////*/
////
////	//std::string const cert =
////	//	"-----BEGIN CERTIFICATE-----\n"
////	//	"MIIDaDCCAlCgAwIBAgIJAO8vBu8i8exWMA0GCSqGSIb3DQEBCwUAMEkxCzAJBgNV\n"
////	//	"BAYTAlVTMQswCQYDVQQIDAJDQTEtMCsGA1UEBwwkTG9zIEFuZ2VsZXNPPUJlYXN0\n"
////	//	"Q049d3d3LmV4YW1wbGUuY29tMB4XDTE3MDUwMzE4MzkxMloXDTQ0MDkxODE4Mzkx\n"
////	//	"MlowSTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMS0wKwYDVQQHDCRMb3MgQW5n\n"
////	//	"ZWxlc089QmVhc3RDTj13d3cuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA\n"
////	//	"A4IBDwAwggEKAoIBAQDJ7BRKFO8fqmsEXw8v9YOVXyrQVsVbjSSGEs4Vzs4cJgcF\n"
////	//	"xqGitbnLIrOgiJpRAPLy5MNcAXE1strVGfdEf7xMYSZ/4wOrxUyVw/Ltgsft8m7b\n"
////	//	"Fu8TsCzO6XrxpnVtWk506YZ7ToTa5UjHfBi2+pWTxbpN12UhiZNUcrRsqTFW+6fO\n"
////	//	"9d7xm5wlaZG8cMdg0cO1bhkz45JSl3wWKIES7t3EfKePZbNlQ5hPy7Pd5JTmdGBp\n"
////	//	"yY8anC8u4LPbmgW0/U31PH0rRVfGcBbZsAoQw5Tc5dnb6N2GEIbq3ehSfdDHGnrv\n"
////	//	"enu2tOK9Qx6GEzXh3sekZkxcgh+NlIxCNxu//Dk9AgMBAAGjUzBRMB0GA1UdDgQW\n"
////	//	"BBTZh0N9Ne1OD7GBGJYz4PNESHuXezAfBgNVHSMEGDAWgBTZh0N9Ne1OD7GBGJYz\n"
////	//	"4PNESHuXezAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCmTJVT\n"
////	//	"LH5Cru1vXtzb3N9dyolcVH82xFVwPewArchgq+CEkajOU9bnzCqvhM4CryBb4cUs\n"
////	//	"gqXWp85hAh55uBOqXb2yyESEleMCJEiVTwm/m26FdONvEGptsiCmF5Gxi0YRtn8N\n"
////	//	"V+KhrQaAyLrLdPYI7TrwAOisq2I1cD0mt+xgwuv/654Rl3IhOMx+fKWKJ9qLAiaE\n"
////	//	"fQyshjlPP9mYVxWOxqctUdQ8UnsUKKGEUcVrA08i1OAnVKlPFjKBvk+r7jpsTPcr\n"
////	//	"9pWXTO9JrYMML7d+XRSZA1n3856OqZDX4403+9FnXCvfcLZLLKTBvwwFgEFGpzjK\n"
////	//	"UEVbkhd5qstF6qWK\n"
////	//	"-----END CERTIFICATE-----\n";
////
////	//std::string const key =
////	//	"-----BEGIN PRIVATE KEY-----\n"
////	//	"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJ7BRKFO8fqmsE\n"
////	//	"Xw8v9YOVXyrQVsVbjSSGEs4Vzs4cJgcFxqGitbnLIrOgiJpRAPLy5MNcAXE1strV\n"
////	//	"GfdEf7xMYSZ/4wOrxUyVw/Ltgsft8m7bFu8TsCzO6XrxpnVtWk506YZ7ToTa5UjH\n"
////	//	"fBi2+pWTxbpN12UhiZNUcrRsqTFW+6fO9d7xm5wlaZG8cMdg0cO1bhkz45JSl3wW\n"
////	//	"KIES7t3EfKePZbNlQ5hPy7Pd5JTmdGBpyY8anC8u4LPbmgW0/U31PH0rRVfGcBbZ\n"
////	//	"sAoQw5Tc5dnb6N2GEIbq3ehSfdDHGnrvenu2tOK9Qx6GEzXh3sekZkxcgh+NlIxC\n"
////	//	"Nxu//Dk9AgMBAAECggEBAK1gV8uETg4SdfE67f9v/5uyK0DYQH1ro4C7hNiUycTB\n"
////	//	"oiYDd6YOA4m4MiQVJuuGtRR5+IR3eI1zFRMFSJs4UqYChNwqQGys7CVsKpplQOW+\n"
////	//	"1BCqkH2HN/Ix5662Dv3mHJemLCKUON77IJKoq0/xuZ04mc9csykox6grFWB3pjXY\n"
////	//	"OEn9U8pt5KNldWfpfAZ7xu9WfyvthGXlhfwKEetOuHfAQv7FF6s25UIEU6Hmnwp9\n"
////	//	"VmYp2twfMGdztz/gfFjKOGxf92RG+FMSkyAPq/vhyB7oQWxa+vdBn6BSdsfn27Qs\n"
////	//	"bTvXrGe4FYcbuw4WkAKTljZX7TUegkXiwFoSps0jegECgYEA7o5AcRTZVUmmSs8W\n"
////	//	"PUHn89UEuDAMFVk7grG1bg8exLQSpugCykcqXt1WNrqB7x6nB+dbVANWNhSmhgCg\n"
////	//	"VrV941vbx8ketqZ9YInSbGPWIU/tss3r8Yx2Ct3mQpvpGC6iGHzEc/NHJP8Efvh/\n"
////	//	"CcUWmLjLGJYYeP5oNu5cncC3fXUCgYEA2LANATm0A6sFVGe3sSLO9un1brA4zlZE\n"
////	//	"Hjd3KOZnMPt73B426qUOcw5B2wIS8GJsUES0P94pKg83oyzmoUV9vJpJLjHA4qmL\n"
////	//	"CDAd6CjAmE5ea4dFdZwDDS8F9FntJMdPQJA9vq+JaeS+k7ds3+7oiNe+RUIHR1Sz\n"
////	//	"VEAKh3Xw66kCgYB7KO/2Mchesu5qku2tZJhHF4QfP5cNcos511uO3bmJ3ln+16uR\n"
////	//	"GRqz7Vu0V6f7dvzPJM/O2QYqV5D9f9dHzN2YgvU9+QSlUeFK9PyxPv3vJt/WP1//\n"
////	//	"zf+nbpaRbwLxnCnNsKSQJFpnrE166/pSZfFbmZQpNlyeIuJU8czZGQTifQKBgHXe\n"
////	//	"/pQGEZhVNab+bHwdFTxXdDzr+1qyrodJYLaM7uFES9InVXQ6qSuJO+WosSi2QXlA\n"
////	//	"hlSfwwCwGnHXAPYFWSp5Owm34tbpp0mi8wHQ+UNgjhgsE2qwnTBUvgZ3zHpPORtD\n"
////	//	"23KZBkTmO40bIEyIJ1IZGdWO32q79nkEBTY+v/lRAoGBAI1rbouFYPBrTYQ9kcjt\n"
////	//	"1yfu4JF5MvO9JrHQ9tOwkqDmNCWx9xWXbgydsn/eFtuUMULWsG3lNjfst/Esb8ch\n"
////	//	"k5cZd6pdJZa4/vhEwrYYSuEjMCnRb0lUsm7TsHxQrUd6Fi/mUuFU/haC0o0chLq7\n"
////	//	"pVOUFq5mW8p0zbtfHbjkgxyF\n"
////	//	"-----END PRIVATE KEY-----\n";
////
////	//std::string const dh =
////	//	"-----BEGIN DH PARAMETERS-----\n"
////	//	"MIIBCAKCAQEArzQc5mpm0Fs8yahDeySj31JZlwEphUdZ9StM2D8+Fo7TMduGtSi+\n"
////	//	"/HRWVwHcTFAgrxVdm+dl474mOUqqaz4MpzIb6+6OVfWHbQJmXPepZKyu4LgUPvY/\n"
////	//	"4q3/iDMjIS0fLOu/bLuObwU5ccZmDgfhmz1GanRlTQOiYRty3FiOATWZBRh6uv4u\n"
////	//	"tff4A9Bm3V9tLx9S6djq31w31Gl7OQhryodW28kc16t9TvO1BzcV3HjRPwpe701X\n"
////	//	"oEEZdnZWANkkpR/m/pfgdmGPU66S2sXMHgsliViQWpDCYeehrvFRHEdR9NV+XJfC\n"
////	//	"QMUk26jPTIVTLfXmmwU0u8vUkpR7LQKkwwIBAg==\n"
////	//	"-----END DH PARAMETERS-----\n";
////
////	static const std::string key =
////		"-----BEGIN RSA PRIVATE KEY-----\n"
////		"MIIEowIBAAKCAQEAxo9757yQfmCmuuLu4I35MtQAIPtzt3X5SvdE1yCr6PciB9eR\n"
////		"wAZJ5XGsRCPp6wqQh7ZAGVSnbaWEqtSu21u3oucWnqf27iDOkQuoW0QE5KEh0JuK\n"
////		"4lgto7wO391vVt727+V4mRqecN0HNe7DKFIae8lJIRXBuvfE3raAPCa4aL6474G+\n"
////		"jyrwP2+ThaAfrEwKTsYH74FQt8KVaAbAO/+bu6Jx3B8ITTLxAPErg/TJlGCWTxS5\n"
////		"uLMdFQ3QTlDZwYp1yRZQKxGilChJUGW/q/ObdSTluoYvj8INjsJgT0ckga+B85mC\n"
////		"1Ij32KCu+y55Z2z7HYbn/lfuh6OQQzmH1KhNkQIDAQABAoIBAQCe+tlRVVg357j3\n"
////		"X6W1o9cIDFhCEDK5jLrafBrhSGZ8dAsKTl6DakWWcSplsH+lUmMgVhsCbRZVIzaS\n"
////		"9RE/zzK8OtyQkZmTVi8uUTAuSsrEKAOEHFXaHpIETBl4wrpXytPahlfF9lsvsLkK\n"
////		"RK57RSmxPRvRYrMnuSQm0ebgwnvaWJiQ2tslCEkZ9Ppl/a4/BJJ2VQF+Sx1O8bLi\n"
////		"FDbS9LJjbXwk5QSF9DBPgzudMTNmaGNlZ/yo/ZEsmL6k2d3ShvK/MLYpkMnMfoPC\n"
////		"WDboJqf8eMkeSOvdmB6PA9Ub1uy/pFD0p9ln4/XBxQsS3Ftu8mdT+A5SOINGZzdY\n"
////		"LgNoAcVxAoGBAPI3pSX8D0ZVabFH3N22fnPvrZsLV7jtaNPhGTxapZbeDhEbNvAG\n"
////		"BQP4zwjLt0ZQ142FnJZZAgTzsAz7bvNYB/At5/hl5v8z3UKfLWrw3RvXUO1+ulP+\n"
////		"mibFP/ZQVbFqG8NcIgTkNI9sKxlmp8Zbp4oz/XZlCheWot24QmA5mTPVAoGBANHb\n"
////		"5MrOaBQBUsF04IOZg3uDwu1P0pkQQKkotvoFpEkoL29TCZrGDSeGIgNWe1et7lYr\n"
////		"Roz+LNs2zvyWR3dmefacXoNu5ZGTyAWmHwJhp1ivEgiZ7P46R+tvlpT9Ew+aVzEp\n"
////		"xmjUdfcfP/9XUh7GpBCFn8bqi4OC3RqKRps51JzNAoGAbmkzHNeDVvpETY2GfoJb\n"
////		"rhmJN226NQ/zgvHPARYI+XaLTvzq1ArKan8WUNob1y+uslI/iMFWDE/Q5noOn1p3\n"
////		"c+JZJX++BoLrzxykJWVaRQCnYTstUHB0cEvl1i/UgCTwNuNeloA3/VC/bLrAq8jH\n"
////		"3FXKqhdwvEPsRcliaF6ZGWkCgYAfq1FxkYh/TFvSufKPqYEACLhH273qP1uiq3RB\n"
////		"csyCBcByylMuuiiOCF3lpw1iA+ttsYYqDMl0I2dFEuCiEiLhpmNU7k1SlLygrZsM\n"
////		"XvREG9da2O+8xcrIqsRMo4xW1HHIB4fblgRfUKX1wJWx80QbAi9Ec2yuYfc/5BIX\n"
////		"priBGQKBgCQpr65vbO/i58h+3rBpYaBmLwJ6Lr51eCTSo2RyFPAH9wRy+c0S4Pka\n"
////		"ocfJafR7BRZn9mK8SrTW+i6HjioO7DdZ/KgZwMMxFxq57/h8ZYT+Ni7YeepXd5tg\n"
////		"yrTWdxDsTvzx/ij3HRWwwkHo8XjMO4rohat3JMjp7o+c2vZ9ONv6\n"
////		"-----END RSA PRIVATE KEY-----";
////
////	static const std::string cert =
////		"-----BEGIN CERTIFICATE-----\n"
////		"MIIFqDCCBJCgAwIBAgIQBB6xHeishzP2PUJFiEmKcTANBgkqhkiG9w0BAQsFADBe\n"
////		"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
////		"d3cuZGlnaWNlcnQuY29tMR0wGwYDVQQDExRSYXBpZFNTTCBSU0EgQ0EgMjAxODAe\n"
////		"Fw0yMDAzMTEwMDAwMDBaFw0yMTAzMTExMjAwMDBaMBQxEjAQBgNVBAMMCSoudXBr\n"
////		"Lm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMaPe+e8kH5gprri\n"
////		"7uCN+TLUACD7c7d1+Ur3RNcgq+j3IgfXkcAGSeVxrEQj6esKkIe2QBlUp22lhKrU\n"
////		"rttbt6LnFp6n9u4gzpELqFtEBOShIdCbiuJYLaO8Dt/db1be9u/leJkannDdBzXu\n"
////		"wyhSGnvJSSEVwbr3xN62gDwmuGi+uO+Bvo8q8D9vk4WgH6xMCk7GB++BULfClWgG\n"
////		"wDv/m7uicdwfCE0y8QDxK4P0yZRglk8UubizHRUN0E5Q2cGKdckWUCsRopQoSVBl\n"
////		"v6vzm3Uk5bqGL4/CDY7CYE9HJIGvgfOZgtSI99igrvsueWds+x2G5/5X7oejkEM5\n"
////		"h9SoTZECAwEAAaOCAqowggKmMB8GA1UdIwQYMBaAFFPKF1n8a8ADIS8aruSqqByC\n"
////		"Vtp1MB0GA1UdDgQWBBRtzVU13eusG6Epih57skwhsW0leTAdBgNVHREEFjAUggkq\n"
////		"LnVway5uZXSCB3Vway5uZXQwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\n"
////		"AQUFBwMBBggrBgEFBQcDAjA+BgNVHR8ENzA1MDOgMaAvhi1odHRwOi8vY2RwLnJh\n"
////		"cGlkc3NsLmNvbS9SYXBpZFNTTFJTQUNBMjAxOC5jcmwwTAYDVR0gBEUwQzA3Bglg\n"
////		"hkgBhv1sAQIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29t\n"
////		"L0NQUzAIBgZngQwBAgEwdQYIKwYBBQUHAQEEaTBnMCYGCCsGAQUFBzABhhpodHRw\n"
////		"Oi8vc3RhdHVzLnJhcGlkc3NsLmNvbTA9BggrBgEFBQcwAoYxaHR0cDovL2NhY2Vy\n"
////		"dHMucmFwaWRzc2wuY29tL1JhcGlkU1NMUlNBQ0EyMDE4LmNydDAJBgNVHRMEAjAA\n"
////		"MIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYApLkJkLQYWBSHuxOizGdwCjw1mAT5\n"
////		"G9+443fNDsgN3BAAAAFwyRUzeQAABAMARzBFAiAf5V/Q1s+uCeNx2ZLdd2kQ7c5I\n"
////		"Ig8fL3NFANy6pmUZPwIhAJxiTWVpHAaw6vfqUMIc2yWeAIsD1RCybpWvp+Kzo4AZ\n"
////		"AHYAXNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDsoAAAFwyRUzvgAABAMA\n"
////		"RzBFAiAvQpmLtTUoM+8ApI0wxf/jKKOPtY2A6E9BR2CqTtUwFgIhAJv/58T64Lj6\n"
////		"2m06o6zbUaZsNicBQulwg5FTfPUlDPT1MA0GCSqGSIb3DQEBCwUAA4IBAQASjfTh\n"
////		"2c8bMmZlPx9OBDyTuOK5BfEHhguFBV4Qhv4MXsRMPZQk7eN+3XV/9KSYXwz67EvB\n"
////		"wQR4JeG0SHrlHfLIDqwMj0yekPwovPbMGgz3crwiwggPkA3r3xhMiaGWYwYd5ppP\n"
////		"t1xZP9DhGqRWaX60MiIQ50RT1lGpEUjyqN3GpDSF/bc16JBgAHz9sjH6JdW/cLou\n"
////		"R+gRRbzuln/Exlq/iHQpjd/BMfgeTZJRKjNN4nQ3Pj6VfuBpTO81qa/bA4gFehFW\n"
////		"3yIkg/KlkHGoEblBzybwyghemB476HtcjQqetMWznDu7DkC9HgRRoK7G1l3CcgyY\n"
////		"A1wt7MQ/TMWODKz3\n"
////		"-----END CERTIFICATE-----";
////
////	ctx.set_password_callback(
////		[](std::size_t,
////			boost::asio::ssl::context_base::password_purpose)
////		{
////			return "test";
////		});
////
////	ctx.set_verify_mode(boost::asio::ssl::context::verify_peer | boost::asio::ssl::context::verify_fail_if_no_peer_cert);
////	ctx.set_options(
////		boost::asio::ssl::context::default_workarounds |
////		boost::asio::ssl::context::no_sslv2 |
////		boost::asio::ssl::context::single_dh_use);
////
////	boost::system::error_code ec;
////	ctx.use_certificate_chain_file("./crt.crt",ec);
////	ctx.use_private_key_file("./key.key",ssl::context::pem,ec);
////	//ctx.use_certificate_chain(
////	//	boost::asio::buffer(cert.data(), cert.size()));
////
////	//ctx.use_private_key(
////	//	boost::asio::buffer(key.data(), key.size()),
////	//	boost::asio::ssl::context::file_format::pem);
////
////
////	//ctx.use_tmp_dh(
////	//	boost::asio::buffer(dh.data(), dh.size()));
////}
////
////int main()
////{
////	auto const address = net::ip::make_address("0.0.0.0");
////	auto const port = static_cast<unsigned short>(std::atoi("443"));
////	auto const doc_root = std::make_shared<std::string>(".");
////	auto const threads = 1;;
////
////	// The io_context is required for all I/O
////	net::io_context ioc{ threads };
////
////	// The SSL context is required, and holds certificates
////	ssl::context ctx{ ssl::context::tlsv12 };
////
////	// This holds the self-signed certificate used by the server
////	load_server_certificate(ctx);
////
////	// Create and launch a listening port
////	std::make_shared<listener>(
////		ioc,
////		ctx,
////		tcp::endpoint{ address, port },
////		doc_root)->run();
////
////	// Run the I/O service on the requested number of threads
////	std::vector<std::thread> v;
////	v.reserve(threads - 1);
////	for (auto i = threads - 1; i > 0; --i)
////		v.emplace_back(
////			[&ioc]
////			{
////				ioc.run();
////			});
////	ioc.run();
////
////	return EXIT_SUCCESS;
////}
////
////#include <iostream>
////#include <string>
////
////#if __GNUC__ >= 3
////#define likely(x) __builtin_expect(!!(x), 1)
////#define unlikely(x) __builtin_expect(!!(x), 0)
////#else
////#define likely(x) (x)
////#define unlikely(x) (x)
////#endif
////
////#ifdef _MSC_VER
////#define ALIGNED(n) _declspec(align(n))
////#else
////#define ALIGNED(n) __attribute__((aligned(n)))
////#endif
////
////#define IS_PRINTABLE_ASCII(c) ((unsigned char)(c)-040u < 0137u)
////
////#define CHECK_EOF()  \
////    if (buf == buf_end) { \
////        return NULL;  \
////    }
////
////#define EXPECT_CHAR_NO_CHECK(ch)\
////    if (*buf++ != ch) {\
////        return false;\
////    }
////
////#define EXPECT_CHAR_NO_CHECK_EX(ch)\
////    if (*buf++ != ch) {\
////        return NULL;\
////    }
////
////#define EXPECT_CHAR(ch) \
////    CHECK_EOF();  \
////    EXPECT_CHAR_NO_CHECK_EX(ch);
////
////#define PARSE_INT(valp_, mul_) \
////    if (*buf < '0' || '9' < *buf) { \
////        buf++; \
////        return false; \
////    } \
////    *(valp_) = (mul_) * (*buf++ - '0');
////
////#define PARSE_INT_3(valp_) \
////    do { \
////        int res_ = 0; \
////        PARSE_INT(&res_, 100)  \
////        *valp_ = res_;  \
////        PARSE_INT(&res_, 10)  \
////        *valp_ += res_; \
////        PARSE_INT(&res_, 1)  \
////        *valp_ += res_;  \
////    } while (0)
////
////
////static const char* get_token_to_eol(const char* buf, const char* buf_end, const char** token, size_t& token_len) {
////	const char* token_start = buf;
////
////#ifdef __SSE4_2__
////	static const char ranges1[] = "\0\010"
////		/* allow HT */
////		"\012\037"
////		/* allow SP and up to but not including DEL */
////		"\177\177"
////		/* allow chars w. MSB set */
////		;
////	int found;
////	buf = findchar_fast(buf, buf_end, ranges1, sizeof(ranges1) - 1, &found);
////	if (found)
////		goto FOUND_CTL;
////#else
////	/* find non-printable char within the next 8 bytes, this is the hottest code; manually inlined */
////	while (likely(buf_end - buf >= 8)) {
////#define DOIT() \
////    do {  \
////        if (unlikely(!IS_PRINTABLE_ASCII(*buf))) \
////            goto NonPrintable; \
////        ++buf;  \
////    } while (0)
////		DOIT();
////		DOIT();
////		DOIT();
////		DOIT();
////		DOIT();
////		DOIT();
////		DOIT();
////		DOIT();
////#undef DOIT
////		continue;
////	NonPrintable:
////		if ((likely((unsigned char)*buf < '\040') && likely(*buf != '\011')) || unlikely(*buf == '\177')) {
////			goto FOUND_CTL;
////		}
////		++buf;
////	}
////#endif
////	for (;; ++buf) {
////		CHECK_EOF();
////		if (unlikely(!IS_PRINTABLE_ASCII(*buf))) {
////			if ((likely((unsigned char)*buf < '\040') && likely(*buf != '\011')) || unlikely(*buf == '\177')) {
////				goto FOUND_CTL;
////			}
////		}
////	}
////FOUND_CTL:
////	if (likely(*buf == '\015')) {
////		++buf;
////		EXPECT_CHAR('\012');
////		token_len = buf - 2 - token_start;
////	}
////	else if (*buf == '\012') {
////		token_len = buf - token_start;
////		++buf;
////	}
////	else {
////		return NULL;
////	}
////	*token = token_start;
////
////	return buf;
////}
////
////static bool check_http_header(const char* buf_start, size_t len, size_t& split_pos)
////{
////	const char* buf = buf_start;
////	const char* buf_end = buf + len;
////
////	/* parse "HTTP/1.x" */
////	if (buf_end - buf < 9) {
////		return false;
////	}
////
////	EXPECT_CHAR_NO_CHECK('H');
////	EXPECT_CHAR_NO_CHECK('T');
////	EXPECT_CHAR_NO_CHECK('T');
////	EXPECT_CHAR_NO_CHECK('P');
////	EXPECT_CHAR_NO_CHECK('/');
////	EXPECT_CHAR_NO_CHECK('1');
////	EXPECT_CHAR_NO_CHECK('.');
////	int version = 0;
////	PARSE_INT(&version, 1);
////
////	/* skip space */
////	if (*buf++ != ' ') {
////		return false;
////	}
////	/* parse status code, we want at least [:digit:][:digit:][:digit:]<other char> to try to parse */
////	if (buf_end - buf < 4) {
////		return false;
////	}
////
////	int status = 0;
////	PARSE_INT_3(&status);
////
////	/* skip space */
////	if (*buf++ != ' ') {
////		return false;
////	}
////
////	const char* msg = nullptr;
////	const char** temp_msg = &msg;
////	*temp_msg = nullptr;
////	size_t msg_len = 0;
////	/* get message */
////	if ((buf = get_token_to_eol(buf, buf_end, temp_msg, msg_len)) == NULL) {
////		return false;
////	}
////
////	split_pos = buf - buf_start;
////	return true;
////}
////
////int main()
////{
////	std::string co_data_ = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nLast-Modified: Thu, 24 Sep 2020 05:22:36 GMT\r\nAccept-Ranges: bytes\r\n";
////	size_t 	length = co_data_.size();
////
////	size_t split_pos = 0;
////	bool falg = check_http_header(&co_data_[0], length, split_pos);
////
////	return 0;
//////}
////
////#include <iostream>
////
////int main()
////{
////	const char* ptr = nullptr;//可以通过二级指针去修改
////	//const char**temp_str =&ptr;
////	//*temp_str = "123";
////	const char**temp_str = nullptr;
////	temp_str = &ptr;
////	*temp_str = "123";
////
////	std::string str;
////	str.resize(3);
////	//memcpy(&str[0], ptr,3); //写法一
////	memcpy(&str[0],*temp_str,3);//写法二
////	//*ptr = "345";//抱歉不能修改
////}
//
////#include <iostream>
////#include <array>
////
////int main()
////{
////	std::array<int, 5>ints;
////	//ints.fill(60);
////	size_t max_size_ = ints.max_size();
////	//适用于模板推到
////	size_t max_size1 = std::tuple_size<decltype(ints)>::value;
////
////	//using T = std::tuple_element<0, decltype(ints)>::type; c++14左右的写法 
////	//T a = 1;
////
////	typename std::tuple_element<0, decltype(ints)>::type a = 1;//c++11的写法
////}
//
////#include<iostream>
////#include <string>
////#include <vector>
////#include"nlohmann_json.hpp"
////
////void get_bool(bool& src_ssl)
////{
////	src_ssl = false;
////}
////
////bool is_number(const char*str,size_t data_size)
////{
////	size_t count = 0;
////	while (count <data_size){
////		if (*str <'0'||'9' <*str){
////			return false;
////		}
////
////		++count;
////		str++;
////	}
////
////	return true;
////}
////
////void create_json_array(std::string& js_str,const std::vector<std::string>&data)
////{
////	size_t data_size = data.size();
////	js_str += "[";
////	size_t format_count = 0;
////
////	for (size_t index = 0;index < data_size;++index) {
////		js_str += "\""+data[index]+"\"";
////		++format_count;
////		if (format_count <data_size){
////			js_str += ",";
////		}
////
////	}
////
////	js_str += "]";
////}
////
////int main()
////{
////	std::vector<std::string>vec{"192.168.5.22","192.168.5.83","192.168.5.121"};
////	std::vector<std::string>vec1;
////	std::string json_str;
////	create_json_array(json_str, vec);
////
////	nlohmann::json js(vec);
////	std::string temp_js_str = js.dump();
////
////	nlohmann::json js_array = nlohmann::json::parse(json_str);
////	auto iter_begin = js_array.begin();
////	for (;iter_begin != js_array.end();++iter_begin) {
////		vec1.push_back(*iter_begin);
////	}
////	int test_v = 0;
////	std::string test_str = std::to_string(test_v);
////
////	std::string data = "00";
////
////	bool falg = is_number(data.c_str(), data.size());
////	bool src_ssl = true;
////	get_bool(src_ssl);
////
////	std::string http_info;
////	std::string https_cfg_str = "443=445+http";
////	auto pos = https_cfg_str.find("=");
////	if (pos == std::string::npos){
////		return 0;
////	}
////
////	std::string forwar_port = https_cfg_str.substr(0, pos);
////	std::string src_port;
////	std::string right_str = https_cfg_str.substr(pos+1, https_cfg_str.size());
////	src_port = right_str;h
////
////	pos = right_str.find("+");
////	if (pos !=std::string::npos) {
////		src_port = right_str.substr(0, pos);
////		http_info = right_str.substr(pos + 1,right_str.size());
////	}
////}
//
////#include <boost/beast/core.hpp>
////#include <boost/beast/http.hpp>
////#include <boost/beast/version.hpp>
////#include <boost/asio/dispatch.hpp>
////#include <boost/asio/strand.hpp>
////#include <boost/config.hpp>
////#include <algorithm>
////#include <cstdlib>
////#include <functional>
////#include <iostream>
////#include <memory>
////#include <string>
////#include <thread>
////#include <vector>
////
////namespace beast = boost::beast;         // from <boost/beast.hpp>
////namespace http = beast::http;           // from <boost/beast/http.hpp>
////namespace net = boost::asio;            // from <boost/asio.hpp>
////using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>
////
////// Return a reasonable mime type based on the extension of a file.
////beast::string_view
////mime_type(beast::string_view path)
////{
////	using beast::iequals;
////	auto const ext = [&path]
////	{
////		auto const pos = path.rfind(".");
////		if (pos == beast::string_view::npos)
////			return beast::string_view{};
////		return path.substr(pos);
////	}();
////	if (iequals(ext, ".htm"))  return "text/html";
////	if (iequals(ext, ".html")) return "text/html";
////	if (iequals(ext, ".php"))  return "text/html";
////	if (iequals(ext, ".css"))  return "text/css";
////	if (iequals(ext, ".txt"))  return "text/plain";
////	if (iequals(ext, ".js"))   return "application/javascript";
////	if (iequals(ext, ".json")) return "application/json";
////	if (iequals(ext, ".xml"))  return "application/xml";
////	if (iequals(ext, ".swf"))  return "application/x-shockwave-flash";
////	if (iequals(ext, ".flv"))  return "video/x-flv";
////	if (iequals(ext, ".png"))  return "image/png";
////	if (iequals(ext, ".jpe"))  return "image/jpeg";
////	if (iequals(ext, ".jpeg")) return "image/jpeg";
////	if (iequals(ext, ".jpg"))  return "image/jpeg";
////	if (iequals(ext, ".gif"))  return "image/gif";
////	if (iequals(ext, ".bmp"))  return "image/bmp";
////	if (iequals(ext, ".ico"))  return "image/vnd.microsoft.icon";
////	if (iequals(ext, ".tiff")) return "image/tiff";
////	if (iequals(ext, ".tif"))  return "image/tiff";
////	if (iequals(ext, ".svg"))  return "image/svg+xml";
////	if (iequals(ext, ".svgz")) return "image/svg+xml";
////	return "application/text";
////}
////
////// Append an HTTP rel-path to a local filesystem path.
////// The returned path is normalized for the platform.
////std::string
////path_cat(
////	beast::string_view base,
////	beast::string_view path)
////{
////	if (base.empty())
////		return std::string(path);
////	std::string result(base);
////#ifdef BOOST_MSVC
////	char constexpr path_separator = '\\';
////	if (result.back() == path_separator)
////		result.resize(result.size() - 1);
////	result.append(path.data(), path.size());
////	for (auto& c : result)
////		if (c == '/')
////			c = path_separator;
////#else
////	char constexpr path_separator = '/';
////	if (result.back() == path_separator)
////		result.resize(result.size() - 1);
////	result.append(path.data(), path.size());
////#endif
////	return result;
////}
////
////// This function produces an HTTP response for the given
////// request. The type of the response object depends on the
////// contents of the request, so the interface requires the
////// caller to pass a generic lambda for receiving the response.
////template<
////	class Body, class Allocator,
////	class Send>
////	void
////	handle_request(
////		beast::string_view doc_root,
////		http::request<Body, http::basic_fields<Allocator>>&& req,
////		Send&& send)
////{
////
////	std::cout << req << std::endl;
////
////	std::string body = "hello world";
////	// Respond to GET request
////	http::response<http::string_body>res;
////	res.body() = body;
////	res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
////	res.set(http::field::content_type,"text/plain");
////	res.content_length(body.size());
////	res.prepare_payload();
////	return send(std::move(res));
////}
////
//////------------------------------------------------------------------------------
////
////// Report a failure
////void
////fail(beast::error_code ec, char const* what)
////{
////	std::cerr << what << ": " << ec.message() << "\n";
////}
////
////// Handles an HTTP server connection
////class session : public std::enable_shared_from_this<session>
////{
////	// This is the C++11 equivalent of a generic lambda.
////	// The function object is used to send an HTTP message.
////	struct send_lambda
////	{
////		session& self_;
////
////		explicit
////			send_lambda(session& self)
////			: self_(self)
////		{
////		}
////
////		template<bool isRequest, class Body, class Fields>
////		void
////			operator()(http::message<isRequest, Body, Fields>&& msg) const
////		{
////			// The lifetime of the message has to extend
////			// for the duration of the async operation so
////			// we use a shared_ptr to manage it.
////			auto sp = std::make_shared<
////				http::message<isRequest, Body, Fields>>(std::move(msg));
////
////			// Store a type-erased version of the shared
////			// pointer in the class to keep it alive.
////			self_.res_ = sp;
////
////			// Write the response
////			http::async_write(
////				self_.stream_,
////				*sp,
////				beast::bind_front_handler(
////					&session::on_write,
////					self_.shared_from_this(),
////					sp->need_eof()));
////		}
////	};
////
////	beast::tcp_stream stream_;
////	beast::flat_buffer buffer_;
////	std::shared_ptr<std::string const> doc_root_;
////	http::request<http::string_body> req_;
////	std::shared_ptr<void> res_;
////	send_lambda lambda_;
////
////public:
////	// Take ownership of the stream
////	session(
////		tcp::socket&& socket,
////		std::shared_ptr<std::string const> const& doc_root)
////		: stream_(std::move(socket))
////		, doc_root_(doc_root)
////		, lambda_(*this)
////	{
////	}
////
////	// Start the asynchronous operation
////	void
////		run()
////	{
////		// We need to be executing within a strand to perform async operations
////		// on the I/O objects in this session. Although not strictly necessary
////		// for single-threaded contexts, this example code is written to be
////		// thread-safe by default.
////		net::dispatch(stream_.get_executor(),
////			beast::bind_front_handler(
////				&session::do_read,
////				shared_from_this()));
////	}
////
////	void
////		do_read()
////	{
////		// Make the request empty before reading,
////		// otherwise the operation behavior is undefined.
////		req_ = {};
////
////		// Set the timeout.
////		stream_.expires_after(std::chrono::seconds(30));
////
////		// Read a request
////		http::async_read(stream_, buffer_, req_,
////			beast::bind_front_handler(
////				&session::on_read,
////				shared_from_this()));
////	}
////
////	void
////		on_read(
////			beast::error_code ec,
////			std::size_t bytes_transferred)
////	{
////		boost::ignore_unused(bytes_transferred);
////
////		// This means they closed the connection
////		if (ec == http::error::end_of_stream)
////			return do_close();
////
////		if (ec)
////			return fail(ec, "read");
////
////		// Send the response
////		handle_request(*doc_root_, std::move(req_), lambda_);
////	}
////
////	void
////		on_write(
////			bool close,
////			beast::error_code ec,
////			std::size_t bytes_transferred)
////	{
////		boost::ignore_unused(bytes_transferred);
////
////		if (ec)
////			return fail(ec, "write");
////
////		if (close)
////		{
////			// This means we should close the connection, usually because
////			// the response indicated the "Connection: close" semantic.
////			return do_close();
////		}
////
////		// We're done with the response so delete it
////		res_ = nullptr;
////
////		// Read another request
////		do_read();
////	}
////
////	void
////		do_close()
////	{
////		// Send a TCP shutdown
////		beast::error_code ec;
////		stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
////
////		// At this point the connection is closed gracefully
////	}
////};
////
//////------------------------------------------------------------------------------
////
////// Accepts incoming connections and launches the sessions
////class listener : public std::enable_shared_from_this<listener>
////{
////	net::io_context& ioc_;
////	tcp::acceptor acceptor_;
////	std::shared_ptr<std::string const> doc_root_;
////
////public:
////	listener(
////		net::io_context& ioc,
////		tcp::endpoint endpoint,
////		std::shared_ptr<std::string const> const& doc_root)
////		: ioc_(ioc)
////		, acceptor_(net::make_strand(ioc))
////		, doc_root_(doc_root)
////	{
////		beast::error_code ec;
////
////		// Open the acceptor
////		acceptor_.open(endpoint.protocol(), ec);
////		if (ec)
////		{
////			fail(ec, "open");
////			return;
////		}
////
////		// Allow address reuse
////		acceptor_.set_option(net::socket_base::reuse_address(true), ec);
////		if (ec)
////		{
////			fail(ec, "set_option");
////			return;
////		}
////
////		// Bind to the server address
////		acceptor_.bind(endpoint, ec);
////		if (ec)
////		{
////			fail(ec, "bind");
////			return;
////		}
////
////		// Start listening for connections
////		acceptor_.listen(
////			net::socket_base::max_listen_connections, ec);
////		if (ec)
////		{
////			fail(ec, "listen");
////			return;
////		}
////	}
////
////	// Start accepting incoming connections
////	void
////		run()
////	{
////		do_accept();
////	}
////
////private:
////	void
////		do_accept()
////	{
////		// The new connection gets its own strand
////		acceptor_.async_accept(
////			net::make_strand(ioc_),
////			beast::bind_front_handler(
////				&listener::on_accept,
////				shared_from_this()));
////	}
////
////	void
////		on_accept(beast::error_code ec, tcp::socket socket)
////	{
////		if (ec)
////		{
////			fail(ec, "accept");
////		}
////		else
////		{
////			// Create the session and run it
////			std::make_shared<session>(
////				std::move(socket),
////				doc_root_)->run();
////		}
////
////		// Accept another connection
////		do_accept();
////	}
////};
////
//////------------------------------------------------------------------------------
////
////int main()
////{
////	std::vector<int>datas{1,2,3,4,5,6};
////	size_t size = datas.size();
////	size_t data_size = size;
////	for (size_t index = 0;index < size;++index) {
////		--data_size;
////	}
////
////	auto const address = net::ip::make_address("0.0.0.0");
////	auto const port = static_cast<unsigned short>(std::atoi("8080"));
////	auto const doc_root = std::make_shared<std::string>(".");
////	auto const threads = 1;
////
////	// The io_context is required for all I/O
////	net::io_context ioc{ threads };
////
////	// Create and launch a listening port
////	std::make_shared<listener>(
////		ioc,
////		tcp::endpoint{ address, port },
////		doc_root)->run();
////
////	// Run the I/O service on the requested number of threads
////	std::vector<std::thread> v;
////	v.reserve(threads - 1);
////	for (auto i = threads - 1; i > 0; --i)
////		v.emplace_back(
////			[&ioc]
////			{
////				ioc.run();
////			});
////	ioc.run();
////
////	return EXIT_SUCCESS;
////}
//
////#include<iostream>
////#include<string>
////
////int main()
////{
////	std::string ip_port = "192.168.5.212:8039";
////	std::string ip;
////	auto pos = ip_port.rfind(":",ip_port.size());
////	if (pos == std::string::npos){
////		return 0;
////	}
////
////	ip = ip_port.substr(0, pos);
////	std::string port = ip_port.substr(pos+1, ip_port.size());
////}
//
////#include<iostream>
////#include <shared_mutex>
////
////int main()
////{
////	//共享锁
////	std::shared_mutex mutex;
////	mutex.lock_shared();
////	mutex.unlock_shared();
//////#ifndef DEBUG
//////	std::cout << "release" << std::endl;
//////#else
//////	std::cout << "debug" << std::endl;
//////#endif
////}
//
////#include <iostream>
////#include <string>
////#include <vector>
////#include <boost/algorithm/string.hpp>
////
////struct rotbot_info
////{
////	std::string ip;
////	std::string port;
////};
////
////std::vector<rotbot_info>rotbot_infos;
////
////void split(std::vector<std::string>&dst_strs,const std::string& src_str, const std::string& delimiter)
////{
////	if (src_str.empty()){
////		return;
////	}
////
////	char* src = strtok(const_cast<char*>(src_str.c_str()), delimiter.c_str());
////	while (src != nullptr){
////		dst_strs.emplace_back(src);
////		src = strtok(nullptr, delimiter.c_str());
////	}
////}
////
////int main()
////
////{
////	std::string host = "127.0.0.1:2181,127.0.0.1:8950";
////
////	std::vector<std::string> strs;
////	split(strs, host, ",");
////	int value = 10;
////
////	//std::string host = "127.0.0.1:2181,127.0.0.1?2182,"
////	//	"127.0.0.1:2183,127.0.0.1:2184,127.0.0.1:2185";
////
////	//std::vector<std::string> strs;
////	//split(strs, host, ",");
////	//boost::split(strs, host, boost::is_any_of(","));
////
////	//size_t pos =0;
////	//size_t data_size = host.size();
////	//while (pos <data_size){
////	//	auto find_pos = host.find(":", pos);
////	//	if (find_pos == std::string::npos){
////	//		continue;
////	//	}
////
////	//	rotbot_info info;
////	//	info.ip = host.substr(pos, find_pos- pos);
////
////	//	auto find_pos_r = host.find(",", pos);
////	//	if (find_pos_r != std::string::npos){
////	//		info.port = host.substr(find_pos + 1, find_pos_r - find_pos-1);
////	//		pos = (find_pos_r + 1);
////	//	}else {
////	//		info.port = host.substr(find_pos + 1, data_size - find_pos-1);
////	//		pos = data_size;
////	//	}
////
////	//	rotbot_infos.push_back(info);
////	//}
////}
//
////#include<iostream>
////#include<memory>
////
////class A
////{
////public:
////	A() = default;
////	virtual ~A() = default;
////	void display1()
////	{
////		display();
////	}
////
////	virtual void display()
////	{
////		std::cout << "A" << std::endl;
////	}
////};
////
////class B :public A
////{
////public:
////	B() = default;
////	virtual ~B() = default;
////	virtual void display()
////	{
////		std::cout << "B" << std::endl;
////	}
////};
////
////int main()
////{
////	std::make_shared<B>()->display1();
////}
//
////#include <iostream>
////#include <memory>
////#include <functional>
////
////using  FuncObserver = std::function<void()>;
////
////class B;
////class A:public std::enable_shared_from_this<A>
////{
////public:
////	A() {
////		
////	}
////
////	void init_conn()
////	{
////		f_ = [this]() {
////			std::cout << "test" << std::endl;
////		};
////
////		ptr_ = std::make_shared<B>(f_);
////	}
////
////	virtual ~A() {
////		std::cout << "~A()" << std::endl;
////	}
////
////	const auto& get_ptrB()
////	{
////		return ptr_;
////	}
////private:
////	FuncObserver f_;
////	std::shared_ptr<B>ptr_{};
////};
////
////class B:public std::enable_shared_from_this<B>
////{
////public:
////	B(const FuncObserver& f):f_(f) {
////
////	}
////
////	virtual ~B() {
////		std::cout << "~B()" << std::endl;
////	}
////
////private:
////	FuncObserver f_;
////};
////
////int main()
////{
////	auto ptr = std::make_shared<A>();
////	ptr->init_conn();
////
////	auto ptr1 = ptr->get_ptrB();
////}
//
////#include<iostream>
////
//////直接使用,不需要using
////inline namespace B
////{
////	class A
////	{
////	public:
////		A() = default;
////		~A() = default;
////		void display() {
////			std::cout << "a" << std::endl;
////		}
////	};
////}
////
////int main()
////{
////	A a;
////}
//
//
////
////#include <iostream>
////#include <boost/json.hpp>
////
////#include <string>
////#include <fstream>
////#include <iostream>
////
////int main()
////{
////	boost::json::object js;
////	js["111"] = 2;
////	js["222"] = 100;
////}
//
////#include<iostream>
////#include<boost/asio.hpp>
////#include <boost/asio/steady_timer.hpp>
////#include <thread>
////
////void print(const boost::system::error_code& e);
////
////boost::asio::io_context ios;
////boost::asio::steady_timer heart_timer_(ios);
////
////void print(const boost::system::error_code& ec)
////{
////	if (ec) {
////		return;
////	}
////
////	std::cout << "Hello!" << std::endl;
////	heart_timer_.expires_from_now(std::chrono::seconds(10));
////	heart_timer_.async_wait(std::bind(print, std::placeholders::_1));
////}
////
////int main()
////{
////	int count = 1;
////	//heart_timer_.expires_at(std::chrono::steady_clock::now() + std::chrono::seconds(30));
////	heart_timer_.async_wait(std::bind(print, std::placeholders::_1));
////	auto work_(boost::asio::make_work_guard(&ios));
////
////	try {
////		std::thread t([&]() {
////			boost::system::error_code ec;
////			ios.run(ec);
////			});
////	}catch (...) {
////
////	}
////
////
////	while (1) {
////		if (count == 10) {
////			ios.stop();
////		}
////
////		++count;
////		std::this_thread::sleep_for(std::chrono::seconds(1));
////	}
////
////
////}
//
////#include <iostream>
////#include <boost/asio.hpp>
////#include <boost/bind.hpp>
////#include <boost/asio/steady_timer.hpp>
////void print(const boost::system::error_code& e, int& count);
////
////boost::asio::io_context io_ctx;
////boost::asio::steady_timer t(io_ctx);
////
////void print(const boost::system::error_code& e, int& count)
////{
////	std::cout << "Hello!" <<"count:"<<count<<std::endl;
////	++count;
////	t.expires_from_now(std::chrono::seconds(1));
////	t.async_wait(std::bind(print, std::placeholders::_1, count));
////}
////
////int main()
////{
////	int count = 0;
////	t.expires_from_now(std::chrono::seconds(1));
////	t.async_wait(std::bind(print, std::placeholders::_1,count));
////	io_ctx.run();
////	std::cout << "timer: " << count << std::endl;
////	return 0;
////}
//
////#include <vector>
////#include "stream_format.hpp"
////
////int main()
////{
////	write_tream_format write_tream;
////	write_tream.write_header(20002);
////
////	std::string str = "1234";
////	write_tream.write_body(str.c_str(),str.size());
////
////}
//
////#include<iostream>
////#include<sstream>
////
////std::string str_to_hex_str(const char* str)
////{
////	const std::string hex = "0123456789ABCDEF";
////
////	std::size_t data_size = strlen(str);
////	std::stringstream ss;
////	for (std::string::size_type index = 0; index < data_size; ++index) {
////		ss << hex[(unsigned char)str[index] >> 4] << hex[(unsigned char)str[index] & 0xf];
////	}
////
////	return std::move(ss.str());
////}
////
////int main()
////{
////	std::string str = str_to_hex_str("abcdefeg");
////}
//
////#include <iostream>
////#include <string>
////#include <random>
////#include <fstream>
////#include <vector>
////#include <boost/uuid/uuid.hpp>            // uuid class
////#include <boost/uuid/uuid_generators.hpp> // generators
////#include <boost/uuid/uuid_io.hpp>    
////
////std::string create_random_str(std::size_t len)
////{
////	std::random_device r;
////	std::string str;
////	// 选择 1 与 6 间的随机数
////	std::default_random_engine e1(r());
////	std::uniform_int_distribution<int> uniform_dist(0,25);
////
////	for (size_t index =0;index<len;++index){
////		size_t seed = uniform_dist(e1);
////		switch (seed%2)
////		{
////		case 1:
////			str += 'A' + seed;
////		case 2:
////			str += 'a' + seed;
////		default:
////			break;
////		}
////	}
////
////	return std::move(str);
////}
////
////int main()
////{
////	for (int i =1;i<20;++i){
////		std::cout << create_random_str(i) << std::endl;
////	}
////
////	boost::uuids::uuid uuid = boost::uuids::random_generator()();
////	const std::basic_string<unsigned char> check_str =
////		std::basic_string<unsigned char>(uuid.begin(), uuid.end());
////
////	std::string uuid_str(uuid.begin(), uuid.end());
////	//
////	std::ifstream read("D:/参数.txt", std::ios::binary|std::ios::ate);
////	if (!read.is_open()){
////		return 0;
////	}
////
////	//read.seekg(0, std::ios::end);
////	size_t data_size = read.tellg();
////	read.seekg(0, std::ios::beg);
////	std::vector<char>buffer_data;
////	buffer_data.resize(data_size);
////
////	read.read(&buffer_data[0],data_size);
////	read.close();
////}
//
////#include <iostream>
////#include <vector>
////#include <algorithm>
////#include <string>
////
////
////namespace vec {
////
////	template< typename T >
////	class vector {
////		// ...
////	};
////
////} // of vec
////
////int main()
////{
////	std::vector<int> v1; // 标准 vector。
////	vec::vector<int> v2; // 用户定义 vector。
////
////	//v1 = v2; // 错误：v1 与 v2 是不同类型的对象。
////
////	{
////		using namespace std;
////		vector<int> v3; // 同 std::vector
////		v1 = v3; // OK
////	}
////
////	{
////		using vec::vector;
////		vector<int> v4; // 同 vec::vector
////		v2 = v4; // OK
////	}
////
////	std::vector<int>ordinals{ 1,2,3,4,5 };
////
////	//遍历++指定值 
////	std::transform(ordinals.begin(), ordinals.end(), 
////		ordinals.begin(),[](int value)->int {return value + 1;});
////
////	std::for_each(ordinals.begin(), ordinals.end(),
////		[](int value) {std::cout<<value<<std::endl;});
////
////	//std::string s("hello");
////	//std::transform(s.begin(), s.end(), s.begin(),
////	//	[](unsigned char c) -> unsigned char { return std::toupper(c); });
////
////	//std::vector<std::size_t> ordinals;
////	//std::transform(s.begin(), s.end(), std::back_inserter(ordinals),
////	//	[](unsigned char c) -> std::size_t { return c; });
////
////	//std::cout << s << ':';
////	//for (auto ord : ordinals) {
////	//	std::cout << ' ' << ord;
////	//}
////	//std::transform(ordinals.cbegin(), ordinals.cend(), ordinals.cbegin(),
////	//	ordinals.begin(), std::plus<>{});
////
////	//std::cout << '\n';
////	//for (auto ord : ordinals) {
////	//	std::cout << ord << ' ';
////	//}
////	//std::cout << '\n';
////}
//
//  //Derived& derived() {
////return static_cast<Derived&>(*this);
//	//}
////#include <iostream>
////#include<vector>
////#include <map>
////#include <unordered_map>
////#include<string>
////#include <memory>
////
////class base
////{
////public:
////	base() = default;
////	virtual ~base() = default;
////
////	inline virtual void display()
////	{
////
////	}
////};
////
////class dirved :public base 
////{
////public:
////	dirved() = default;
////	virtual ~dirved() = default;
////	inline virtual void display()
////	{
////		std::cout << "dirved" << std::endl;
////	}
////};
////
////union D {
////	D() : i(10) {};
////	~D() = default;
////	int i;
////	double d;
////};
////
////int main()
////{
////	int i = 0x12345678;
////	char value = *(char*)&i;
////	if (*(char*)&i == 0x000000078)
////	{
////		std::cout << "小端" << std::endl;
////	}else {
////		std::cout << "大端" << std::endl;
////	}
////
////	size_t data_size = sizeof(D);
////	std::shared_ptr<base> ptr = std::make_shared<dirved>();
////	ptr->display();
////}
//
////
////#include <tuple>
////#include <iostream>
////#include<memory>
////#include <mutex>
//////#include <optional>
////#include <vector>
////
//////c++14写法 
////template <typename F, typename ...Args>
////void for_each_args1(F&& func, Args...args) {
////	int arr[] = { (std::forward<F>(func)(args),0)... };
////}
////
//////c++17写法折叠表达式  
////template <typename F, typename ...Args>
////void for_each_args(F&& func, Args...args) {
////	//int arr[] = { (std::forward<F>(func)(args),0)... };
////	(std::forward<F>(func)(args),...);
////}
////
////int main()
////{
////	std::vector<int>vec{1,2,3,4,5};
////	//std::optional<std::vector<int>>vec_ptr;
////	//vec_ptr.emplace(vec);
////	std::size(vec);
////	//size_t data_size = vec_ptr->size();
////
////	std::mutex mu;
////	{
////		//std::scoped_lock<std::mutex>lock(mu);
////	}
////
////	mu.lock();
////	mu.unlock();
////	for_each_args([](auto value) {std::cout << value << std::endl;},1,2,3,4);
////}
//
////#include <iostream>
////#include<any>
////#include <vector>
////#include <optional>
////#include<memory>
////#include <algorithm>
////#include <array>
////#include <unordered_map>
////#include <string>
////
////template<typename F,typename...Args>
////void print_for_each(F&&f,Args&&...arg)
////{
////	(...,std::forward<F>(f)(arg));
////}
////
////class A
////{
////public:
////	A() {
////		std::cout << "A()" << std::endl;
////	}
////
////	~A() {
////		std::cout << "~A()" << std::endl;
////	}
////
////};
////int add(int first, int second) { return first + second; }
////
////int main()
////{
////	std::unordered_map<int, int>u_map{ {1,2},{2,3},{3,4} };
////	if (auto iter_find = u_map.find(1); iter_find != u_map.end()) {
////		int i = 10;
////	}
////
////	std::for_each(u_map.begin(), u_map.end(), [](const auto& value) {
////		std::cout << value.first << std::endl;
////		});
////	auto [key, value] = std::pair(1, 2);
////
////	//apply 是直接调用函数
////	//auto add_value = std::apply(add, std::pair(1, 2));
////	std::array<int,2> arr = { 1, 2};
////	auto add_value = std::apply(add, arr);
////	std::any a = 1;
////	std::cout << a.type().name() << ": " << std::any_cast<int>(a) << '\n';
////	//a = 3.14f;//加f的是float类型
////	a = 3.14;
////	//std::cout << a.type().name() << ": " << std::any_cast<float>(a) << '\n';	//这类型不对，直接抛异常
////	std::cout << a.type().name() << ": " << std::any_cast<double>(a) << '\n';
////
////	auto ptr = std::make_shared<A>();
////	ptr.reset(new A);
////	//print_for_each([](auto value) {std::cout << value << std::endl;},1);
////	//print_for_each([](auto value) {std::cout << value << std::endl;},2,3);
////	print_for_each([](const auto value) {std::cout << value << std::endl;},4,5,6);
////	std::vector<int>vec{ 1,2,3,4,5 };
////	//vec.erase(
////	//	std::remove_if(vec.begin(), vec.end(), [](auto value)->bool {return value == 2;}),
////	//	vec.end());
////
////	vec.erase(vec.begin()+2,vec.end());
////	std::optional<std::vector<int>>vec_ptr;
////	vec_ptr.emplace(vec);
////	size_t data_size = (*vec_ptr).size();
////	//size_t data_size = std::size(vec);
////}
////#include <iostream>
////#include <sstream>
////#include <memory>
////#include <boost/make_shared.hpp>
////#include <any>
////#include <variant>
////
////template <typename T, typename U>
////auto add(T t, U u) {
////	return t + u;
////}
////
////class A
////{
////public:
////	A() {
////		std::cout << "A()" << std::endl;
////	}
////
////	~A() {
////		std::cout << "~A()" << std::endl;
////	}
////};
////
////int main()
////{
////	std::variant<int>value123;
////	value123.emplace<int>(1);
////	//auto value1 = test(2);
////	//std::string test123 = "1234";
////	//std::any value2 = test123;
////	//std::string str123 = value2.has_value() ? std::any_cast<std::string>(value2) : "";
////
////	//try
////	//{
////	//	std::cout << value2.type().name() << '\n';
////	//	std::cout << std::any_cast<const char*>(value2) << '\n';
////	//}
////	//catch (const std::bad_any_cast& e)
////	//{
////	//	std::cout << e.what() << '\n';
////	//}
////
////	std::string str = "123";
////	std::stringstream stream(str);//输出才能用这个
////	//auto b_ptr_arr = boost::make_shared<A[]>(3);
////
////	//int* p = new int[] {1, 2, 3};
////	//auto ptr_arr = std::make_shared<int[]>();
////
////	//std::unique_ptr<int[]> up1(new int[10]());
////
////	//C++14以后语法
////	//auto up2 = std::make_unique<A[]>(3);
////
////	//auto sp3(std::shared_ptr<A[]>(new A[3]));
////	
////
////	int value = 0;
////
////	stream >> value;
////}
//
////#include<iostream>
////#include <sstream>
////#include <iomanip>
////#include <chrono>
////#include <type_traits>
////#include <boost/asio.hpp>
////
////enum class A
////{
////
////};
////
////int64_t str_time_to_time_stamp(const std::string& time_str)
////{
////	std::tm tm = {};
////	std::stringstream ss(time_str);
////	ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
////	auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));
////	auto tmp = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch());
////	return tmp.count();
////}
////
////std::chrono::system_clock::time_point str_time_to_time_point(const std::string& time_str)
////{
////	std::tm tm = {};
////	std::stringstream ss(time_str);
////	ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
////	auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));
////	return tp;
////}
////
////int main()
////{
////	A a;
////	std::cout << std::is_enum<decltype(a)>::value << std::endl;
////
////	std::tm tm = {};
////	std::stringstream ss("2020-12-31 17:00:00");
////	ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
////	auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));
////	std::chrono::system_clock::duration d = tp -std::chrono::system_clock::now();
////	boost::asio::io_context ios;
////	boost::asio::steady_timer timer(ios);
////	
////	timer.expires_from_now(d);
////	timer.async_wait([](const boost::system::error_code& ec) {
////		if (ec){
////			return;
////		}
////
////		std::cout << "123" << std::endl;
////		});
////	//timer.expires_at(tp.time_since_epoch());
////	boost::system::error_code ec;
////	ios.run(ec);
////}
//
////#include <iostream>
////#include <vector>
////#include<chrono>
////#include <sstream>
////#include <iomanip>
////#include<mutex>
////#include <fstream>
////#include <filesystem>
////
////std::chrono::system_clock::time_point str_time_to_time_point(const std::string& time_str)
////{
////	std::tm tm = {};
////	std::stringstream ss(time_str);
////	ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");
////	auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));
////
////	return tp;
////}
////
////int main()
////{
////	auto path = std::filesystem::path("G:/test.txt");
////	//后面会追加
////	std::filesystem::resize_file(path,1024*1024*1);
////
////	std::mutex t1;
////	std::mutex t2;
////
////	{
////		//局部锁,一个或多个
////		std::scoped_lock lock(t1, t2);
////	}
////
////	t1.lock();
////	t2.lock();
////	t2.unlock();
////	t1.unlock();
////
////	char src[] = "aaaaaaaaaa";
////	char dst[] = "xyxyxyxyxy";
////
////	// 创建含有整数的 vector
////	std::vector<int> v = { 7, 5, 16, 8 };
////
////	// 添加二个整数到 vector
////	v.push_back(25);
////	v.push_back(13);
////
////	// 迭代并打印 vector 的值
////	for (int n : v) {
////		std::cout << n << '\n';
////	}
////}
//
////#ifdef _WIN32
////#include <filesystem>
////namespace fs = std::filesystem;
////#else
////#include <experimental/filesystem>
////namespace fs = std::experimental::filesystem;
////#endif
////#include<iostream>
////
////
////
////int main()
////{
////	auto path = fs::path("/root/test.txt");
////	//后面会追加
////	fs::resize_file(path, 1024 * 1024 * 1);
////}
//
////#include<iostream>
////#include<string>
////#include <memory>
////#include <algorithm>
////#include <vector>
////#include<sstream>
////#include<mutex>
////
////static void create_json_array(std::string& js_str, const std::vector<std::string>& data)
////{
////	std::ostringstream write;
////	size_t data_size = data.size();
////	write << "[";
////	size_t ele_count = 0;
////
////	for (size_t index = 0;index < data_size;++index) {
////		write << "\"";
////		write << data[index];
////		write<<"\"";
////		++ele_count;
////		if (ele_count < data_size) {
////			write<<",";
////		}
////	}
////
////	write<<"]";
////
////	js_str = write.str();
////}
////
////static bool is_number(const std::string& str)
////{
////	if (str.empty()) {
////		return false;
////	}
////
////	return std::all_of(str.begin(), str.end(),::isdigit);
////}
////
////size_t str_to_num(const std::string& str)
////{
////	size_t data_num = 0;
////	if (!is_number(str)){
////		return data_num;
////	}
////
////	size_t data_count = str.size();
////	for (size_t index =0;index <data_count;++index){
////		data_num *=10;
////		data_num += static_cast<size_t>(str[index] - '0');
////	}
////
////	return data_num;
////}
////
////int main()
////{
////	std::vector<int>vec{1,2,3,4,5,6,7,8,0,9};
////	std::vector<std::string>vecs{"192.168.5.121","192.168.5.86"};
////	std::string str_js;
////	create_json_array(str_js, vecs);
////	//bool falg = std::none_of(vec.begin(), vec.end(),[](auto value){return value < 0;});
////	bool falg = std::any_of(vec.begin(), vec.end(), [](auto value) {return value <=0;});
////	//std::string str = "123456::156";
////
////	//auto pos = str.find(":",6+1);
////	//std::string temp_str = str.substr(pos + 1, str.size());
////	size_t num = str_to_num("*&+_-01@23!");
////}
//
////#include<iostream>
////#include<boost/process.hpp>
////#include "nlohmann_json.hpp"
////
////int main()
////{
////	std::vector<int>vec{ 1,2,3,4,5 };
////	nlohmann::json js(vec);
////
////	std::string str = js.dump();
////
////	std::vector<int> v(10, 2);
////	std::partial_sum(v.cbegin(), v.cend(), v.begin());
////
////}
//
////#include <iostream>
////#include <type_traits>
////using namespace std;
////template<int a, int b>
////typename enable_if<a + b == 233, bool>::type is233()
////{
////    return true;
////}
////template<int a, int b>
////typename enable_if<a + b != 233, bool>::type is233()
////{
////    return false;
////}
////int main()
////{
////    cout << is233<1, 232>() << endl << is233<114514, 1919>();
////    return 0;
////}
//
////#include<iostream>
////#include <mutex>
////#include<atomic>
////
////class my_mutex {
////public:
////	my_mutex() = default;
////	~my_mutex() {
////		if (is_lock_) {
////			unlock();
////		}
////	}
////	void lock() {
////		is_lock_ = true;
////		while (mutx_flag_.test_and_set(std::memory_order_acquire));
////	}
////	void unlock() {
////		is_lock_ = false;
////		mutx_flag_.clear(std::memory_order_release);
////	}
////	bool try_lock() {
////		if (is_lock_) {
////			return false;
////		}
////
////		lock();
////		return true;
////	}
////
////	my_mutex(const my_mutex&) = delete;
////	my_mutex(my_mutex&&) = delete;
////	my_mutex& operator=(const my_mutex&) = delete;
////	my_mutex& operator=(my_mutex&&) = delete;
////private:
////	bool is_lock_ = false;
////	std::atomic_flag mutx_flag_ = ATOMIC_FLAG_INIT;
////};
////
////class test
////{
////public:
////	test() = default;
////	~test() = default;
////	void display()
////	{
////		{
////			std::lock_guard<my_mutex>lock(mutex_);
////		}
////
////		display();
////	}
////private:
////	my_mutex mutex_;
////};												 
////
////int main()
////{
////	for (int i = 0;i < 101;++i){
////		std::cout << (i & 3)+1 << std::endl;
////	}
////
////	test t;
////	t.display();
////}
//
////#include <iostream>
////#include <vector>
////#include <string>
////#include <queue>
////#include <forward_list>
////
////std::vector<std::string>split(const std::string& src_str, const std::string& demil)
////{
////	std::vector<std::string>result;
////
////	if(src_str.empty()){
////		return std::move(result);
////	}
////
////	std::size_t size = src_str.size();
////	size_t pos = 0;
////	size_t start = 0;
////	while (pos <size){
////		pos = src_str.find(demil, start);
////		if (pos !=std::string::npos){
////			result.emplace_back(src_str.substr(start, pos - start));
////		}else {
////			if (start <size){
////				result.emplace_back(src_str.substr(start, size - start));
////			}
////
////			break;
////		}
////
////		++pos;
////		start = pos;
////	}
////
////	return std::move(result);
////}
////
////
////int main()
////{
////	//std::forward_list<int>slist;
////
////	//for (int index =0;index <10;++index){
////	//	slist.push_front(index);
////	//}
////
////	//auto value = *slist.begin();
////	//slist.assign(1, 2);
////	//auto value2 = slist.end();
////	std::queue<int>que;
////	que.push(1);
////	que.push(2);
////	que.push(3);
////
////	int value1 = que.front();
////	que.pop();
////	value1 = que.front();
////	que.pop();
////	value1 = que.front();
////	que.pop();
////
////	auto result = split("192.168.5.22:8951:192.168.212:8080", ":");
////	int i = 0;
////}
//
////#include <iostream>
////
////#define DOCTEST_CONFIG_IMPLEMENT
////#include "doctest.hpp"
////
////int main(int argc, char** argv) {
////	doctest::Context context;
////	context.applyCommandLine(argc, argv);
////
////	int res = context.run(); // run doctest
////
////	// important - query flags (and --exit) rely on the user doing this
////	if (context.shouldExit())
////	{																		  
////		// propagate the result of the tests
////		return res;
////	}
////
////	printf("%s\n", "Hello, World!");
////
////	system("pause");
////	return 0;
////}
////
////int add(int a,int b) {
////	return a + b;
////}
////
////TEST_CASE("testing the add function") {
////	CHECK(add(0,0) == 0);
////	CHECK(add(1,2) == 3);
////	CHECK(add(2,3) == 5);
////	CHECK(add(3,4) == 7);
////	CHECK(add(1,4) == 5);
////}
//
////#include <string>
////#include <sstream>
////#include <iomanip>
////#include <vector>
////
////template <typename T>
////std::string type_to_str(T value, int precision) {
////	std::ostringstream oss;
////	oss.precision(precision);
////	oss <<value;
////
////	return std::move(oss.str());
////}
////
////std::string to_string(int value)
////{
////	std::string temp_str;
////	std::string str;
////	if (value <0){
////		str.append("-");
////		value = (~value)+1;
////	}
////
////	while (value >0){
////		temp_str+=((value%10)+'0');
////		value /= 10;
////	}
////
////	auto riter_beg = temp_str.rbegin();
////	for (;riter_beg != temp_str.rend();++riter_beg){
////		str += *riter_beg;
////	}
////
////	return std::move(str);
////}
////
////int main()
////{
////	int value = -304;
////	std::string str = to_string(value);
////	std::string str1 = type_to_str(value, 2);
////}
//
////#include <cstdlib>
////#include <cstring>
////#include <iostream>
////#include <boost/asio.hpp>
////#include "serialize.h"
////
////using boost::asio::ip::tcp;
////
////enum { max_length = 1024 };
////
////
////class A :public Serializable
////{
////public:
////	A(const std::string& name, const std::string& passwd)
////		:name_(name)
////		, passwd_(passwd) {
////
////	}
////
////	virtual ~A() = default;
////	virtual std::string serialize()
////	{
////		out_stream out;
////		out << name_ << passwd_;
////		return out.str();
////	}
////	virtual unsigned int deserialize(const std::string&str)
////	{
////		return 0;
////	}
////private:
////	std::string name_;
////	std::string passwd_;
////};
////int main(int argc, char* argv[])
////{
////	try
////	{
////
////		boost::asio::io_context io_context;
////		boost::asio::ip::tcp::endpoint ep(boost::asio::ip::address::from_string("127.0.0.1"), 9090);
////		tcp::socket s(io_context);
////		s.connect(ep);
////		//boost::asio::connect(s, ep);
////
////		using namespace std; // For strlen.
////		A a("YINPINGHUA", "56");
////		std::string message = a.serialize();
////		boost::asio::write(s, boost::asio::buffer(message, message.size()));
////
////		//char reply[max_length];
////		//size_t reply_length = boost::asio::read(s,
////		//	boost::asio::buffer(reply, request_length));
////		//std::cout << "Reply is: ";
////		//std::cout.write(reply, reply_length);
////		//std::cout << "\n";
////	}
////	catch (std::exception& e)
////	{
////		std::cerr << "Exception: " << e.what() << "\n";
////	}
////
////	return 0;
////}
//
////#include <iostream>
////#include <boost/asio.hpp>
////
////int main()
////{
////	boost::asio::io_context ios;
////	//boost::asio::io_context::work w(ios);
////	boost::system::error_code ec;
////
////	boost::asio::ip::tcp::acceptor acp(ios);
////	boost::asio::ip::tcp::endpoint ept(boost::asio::ip::tcp::v4(), 9090);
////	acp.open(ept.protocol(), ec);
////	acp.bind(ept,ec);
////	acp.listen(64000, ec);
////
////	acp.async_accept(
////		[](const boost::system::error_code& ec, boost::asio::ip::tcp::socket &&sct) {
////		if (ec){
////			return;
////		}
////
////		sct.send(boost::asio::buffer("1234"));
////		});
////
////	ios.run(ec);
////}
//
////#include <boost/asio.hpp>
////
////int main()
////{
////	boost::asio::io_context io;
////
////	boost::system::error_code ec;
////	io.run(ec);
////}
//
////#include <iostream>
////
//////属于结构性设计模式
////class Implementation
////{
////public:
////	Implementation() = default;
////	virtual~Implementation() = default;
////	virtual std::string OperationImplementation() const = 0;
////};
////
////class A :public Implementation
////{
////public:
////	std::string OperationImplementation() const override
////	{
////		return "ConcreteImplementationA: Here's the result on the platform A.\n";
////	}
////};
////
////class B :public Implementation
////{
////public:
////	std::string OperationImplementation() const override {
////		return "ConcreteImplementationB: Here's the result on the platform B.\n";
////	}
////};
////
////class Abstraction {
////	/**
////	 * @var Implementation
////	 */
////protected:
////	Implementation* implementation_;
////
////public:
////	Abstraction(Implementation* implementation) : implementation_(implementation) {
////	}
////
////	virtual ~Abstraction() {
////	}
////
////	virtual std::string Operation() const {
////		return "Abstraction: Base operation with:\n" +
////			this->implementation_->OperationImplementation();
////	}
////};
////
////class ExtendedAbstraction : public Abstraction {
////public:
////	ExtendedAbstraction(Implementation* implementation) : Abstraction(implementation) {
////	}
////	std::string Operation() const override {
////		return "ExtendedAbstraction: Extended operation with:\n" +
////			this->implementation_->OperationImplementation();
////	}
////};
////
////
////int main()
////{
////	Implementation* implementation = new A;
////	Abstraction* abstraction = new Abstraction(implementation);
////	abstraction->Operation();
////	std::cout << std::endl;
////	delete implementation;
////	delete abstraction;
////
////	implementation = new B;
////	abstraction = new ExtendedAbstraction(implementation);
////	abstraction->Operation();
////
////	delete implementation;
////	delete abstraction;
////}
//
////#include <iostream>
////#include <map>
////#include <vector>
//////
//////using namespace std;
//////class Computer
//////{
//////public:
//////	static void start() {
//////		cout << "电脑正在启动" << endl;
//////	}
//////};
//////class Student
//////{
//////public:
//////	void playGame()
//////	{
//////		//局部变量构成依赖
//////		Computer* computer = new Computer;
//////			//静态方法调用构成依赖
//////			Computer::start();
//////	}
//////};
////
//////创建对象较大时，可以使用
////class Prototype
////{
////public:
////	Prototype() = default;
////	virtual~Prototype() = default;
////
////
////	virtual Prototype* clone() = 0;
////};
////
////class ConcretePrototypeA :public Prototype
////{
////public:
////	ConcretePrototypeA() = default;
////	~ConcretePrototypeA() {}
////
////	ConcretePrototypeA(const ConcretePrototypeA& instance) = default;
////
////	virtual ConcretePrototypeA* clone()
////	{
////		std::cout << "copy of self" << std::endl;
////		return new ConcretePrototypeA(*this);
////	}
////};
////
//////结构性设计模式(享元设计模式)
////class Coordinates {
////public:
////	Coordinates(int x, int y) {
////		this->x = x;
////		this->y = y;
////		std::cout << "Coordinates Hello, x = " << x << " y = " << y << std::endl;
////	}
////	~Coordinates() {
////		std::cout << "Coordinates Bye, x = " << x << " y = " << y << std::endl;
////	}
////	int getX() {
////		return x;
////	}
////	void setX(int x) {
////		this->x = x;
////	}
////	int getY() {
////		return y;
////	}
////	void setY(int y) {
////		this->y = y;
////	}
////private:
////	int x;
////	int y;
////};
////
////class ChessPiece {
////public:
////	virtual ~ChessPiece() = default;
////	virtual std::string getColor() = 0;
////	void display(Coordinates* coord) {
////		std::cout << "棋子颜色：" << getColor() << "，棋子位置：" << "x = " << coord->getX() << "，y = " << coord->getY() << std::endl;
////	};
////protected:
////	ChessPiece() = default;
////	std::string color;
////};
////
////class BlackChessPiece : public ChessPiece {
////public:
////	BlackChessPiece() {
////		std::cout << "BlackChessPiece Hello" << std::endl;
////		color = "黑色";
////	}
////	~BlackChessPiece() override {
////		std::cout << "BlackChessPiece Bye" << std::endl;
////	}
////	std::string getColor() override {
////		return color;
////	}
////};
////
////class WhiteChessPiece : public ChessPiece {
////public:
////	WhiteChessPiece() {
////		std::cout << "WhiteChessPiece Hello" << std::endl;
////		color = "白色";
////	}
////	~WhiteChessPiece() override {
////		std::cout << "WhiteChessPiece Bye" << std::endl;
////	}
////	std::string getColor() override {
////		return color;
////	}
////};
////
/////// FlyweightFactory（享元工厂类）：ChessPieceFactory
////class ChessPieceFactory {
////public:
////	static ChessPieceFactory* getInstance() {
////		static ChessPieceFactory instance;
////		return &instance;
////	}
////	ChessPiece* getChessPiece(const std::string& color) {
////		return mapChessPiece[color];
////	}
////private:
////	ChessPieceFactory() {
////		std::cout << "ChessPieceFactory Hello" << std::endl;
////		mapChessPiece.insert(std::pair<std::string, ChessPiece*>("b", new BlackChessPiece()));
////		mapChessPiece.insert(std::pair<std::string, ChessPiece*>("w", new WhiteChessPiece()));
////	}
////	~ChessPieceFactory() {
////		std::cout << "ChessPieceFactory Bye" << std::endl;
////		auto  iter = mapChessPiece.begin();
////		while (iter != mapChessPiece.end()) {
////			ChessPiece* chessPiece = iter->second;
////			delete chessPiece;
////			iter++;
////		}
////	}
////
////	std::map<std::string, ChessPiece*> mapChessPiece;
////};
////
//////中介模式(行为模式)
////#include <iostream>
////#include <string>
////using namespace std;
////
////class Colleague;
////
////class Mediator {
////public:
////	virtual void Send(string message, Colleague* colleague) = 0;
////	virtual ~Mediator() {}
////};
////
////class Colleague {
////protected:
////	Mediator* mediator;
////public:
////	Colleague(Mediator* m) { mediator = m; }
////};
////
////class ConcreteColleague1 : public Colleague {
////public:
////	ConcreteColleague1(Mediator* m) : Colleague(m) {}
////	void Send(string message) {
////		mediator->Send(message, this);
////	}
////	void Notify(string message) {
////		cout << "ConcreteColleague1 received: " << message << endl;
////	}
////};
////
////class ConcreteColleague2 : public Colleague {
////public:
////	ConcreteColleague2(Mediator* m) : Colleague(m) {}
////	void Send(string message) {
////		mediator->Send(message, this);
////	}
////	void Notify(string message) {
////		cout << "ConcreteColleague2 received: " << message << endl;
////	}
////};
////
////class ConcreteMediator : public Mediator {
////private:
////	ConcreteColleague1* c1;
////	ConcreteColleague2* c2;
////public:
////	void set(ConcreteColleague1* c) { c1 = c; }
////	void set(ConcreteColleague2* c) { c2 = c; }
////	void Send(string message, Colleague* colleague) {
////		if (colleague == c1) c2->Notify(message);
////		else c1->Notify(message);
////	}
////};
////
////
//////行为设计模式(命令模式)
/////**
//// * The Command interface declares a method for executing a command.
//// */
////class Command {
////public:
////	virtual ~Command() {
////	}
////	virtual void Execute() const = 0;
////};
/////**
//// * Some commands can implement simple operations on their own.
//// */
////class SimpleCommand : public Command {
////private:
////	std::string pay_load_;
////
////public:
////	explicit SimpleCommand(std::string pay_load) : pay_load_(pay_load) {
////	}
////	void Execute() const override {
////		std::cout << "SimpleCommand: See, I can do simple things like printing (" << this->pay_load_ << ")\n";
////	}
////};
////
/////**
//// * The Receiver classes contain some important business logic. They know how to
//// * perform all kinds of operations, associated with carrying out a request. In
//// * fact, any class may serve as a Receiver.
//// */
////class Receiver {
////public:
////	void DoSomething(const std::string& a) {
////		std::cout << "Receiver: Working on (" << a << ".)\n";
////	}
////	void DoSomethingElse(const std::string& b) {
////		std::cout << "Receiver: Also working on (" << b << ".)\n";
////	}
////};
////
/////**
//// * However, some commands can delegate more complex operations to other objects,
//// * called "receivers."
//// */
////class ComplexCommand : public Command {
////	/**
////	 * @var Receiver
////	 */
////private:
////	Receiver* receiver_;
////	/**
////	 * Context data, required for launching the receiver's methods.
////	 */
////	std::string a_;
////	std::string b_;
////	/**
////	 * Complex commands can accept one or several receiver objects along with any
////	 * context data via the constructor.
////	 */
////public:
////	ComplexCommand(Receiver* receiver, std::string a, std::string b) : receiver_(receiver), a_(a), b_(b) {
////	}
////	/**
////	 * Commands can delegate to any methods of a receiver.
////	 */
////	void Execute() const override {
////		std::cout << "ComplexCommand: Complex stuff should be done by a receiver object.\n";
////		this->receiver_->DoSomething(this->a_);
////		this->receiver_->DoSomethingElse(this->b_);
////	}
////};
////
/////**
//// * The Invoker is associated with one or several commands. It sends a request to
//// * the command.
//// */
////class Invoker {
////	/**
////	 * @var Command
////	 */
////private:
////	Command* on_start_;
////	/**
////	 * @var Command
////	 */
////	Command* on_finish_;
////	/**
////	 * Initialize commands.
////	 */
////public:
////	~Invoker() {
////		delete on_start_;
////		delete on_finish_;
////	}
////
////	void SetOnStart(Command* command) {
////		this->on_start_ = command;
////	}
////	void SetOnFinish(Command* command) {
////		this->on_finish_ = command;
////	}
////	/**
////	 * The Invoker does not depend on concrete command or receiver classes. The
////	 * Invoker passes a request to a receiver indirectly, by executing a command.
////	 */
////	void DoSomethingImportant() {
////		std::cout << "Invoker: Does anybody want something done before I begin?\n";
////		if (this->on_start_) {
////			this->on_start_->Execute();
////		}
////		std::cout << "Invoker: ...doing something really important...\n";
////		std::cout << "Invoker: Does anybody want something done after I finish?\n";
////		if (this->on_finish_) {
////			this->on_finish_->Execute();
////		}
////	}
////};
/////**
//// * The client code can parameterize an invoker with any commands.
//// */
////
//////行为设计模式(模板方法)
////class abstract_class
////{
////public:
////	abstract_class() = default;
////	virtual ~abstract_class() = default;
////public:
////	void template_mod()const
////	{
////		this->BaseOperation1();
////		this->RequiredOperations1();
////		this->BaseOperation2();
////		this->Hook1();
////		this->RequiredOperation2();
////		this->BaseOperation3();
////		this->Hook2();
////	}
////
////protected:
////	void BaseOperation1() const {
////		std::cout << "AbstractClass says: I am doing the bulk of the work\n";
////	}
////	void BaseOperation2() const {
////		std::cout << "AbstractClass says: But I let subclasses override some operations\n";
////	}
////	void BaseOperation3() const {
////		std::cout << "AbstractClass says: But I am doing the bulk of the work anyway\n";
////	}
////	virtual void RequiredOperations1() const = 0;
////	virtual void RequiredOperation2() const = 0;
////	virtual void Hook1() const {}
////	virtual void Hook2() const {}
////};
////
////class ConcreteClass1 : public abstract_class {
////protected:
////	void RequiredOperations1() const override {
////		std::cout << "ConcreteClass1 says: Implemented Operation1\n";
////	}
////	void RequiredOperation2() const override {
////		std::cout << "ConcreteClass1 says: Implemented Operation2\n";
////	}
////
////};
////
////void ClientCode(abstract_class* class_) {
////	// ...
////	class_->template_mod();
////	// ...
////}
////
////class ConcreteClass2 : public abstract_class {
////protected:
////	void RequiredOperations1() const override {
////		std::cout << "ConcreteClass2 says: Implemented Operation1\n";
////	}
////	void RequiredOperation2() const override {
////		std::cout << "ConcreteClass2 says: Implemented Operation2\n";
////	}
////	void Hook1() const override {
////		std::cout << "ConcreteClass2 says: Overridden Hook1\n";
////	}
////};
////
//////结构性行为模式
//////主题请求
////class Subject
////{
////public:
////	Subject() = default;
////	virtual ~Subject() = default;
////	virtual void request() const= 0 ;
////};
////
////class RealSubject :public Subject
////{
////public:
////	RealSubject() = default;
////	virtual ~RealSubject() = default;
////	virtual void request()const
////	{
////		std::cout << "RealSubject: Handling request.\n";
////	}
////};
////
////class Proxy : public Subject {
////	/**
////	 * @var RealSubject
////	 */
////private:
////	RealSubject* real_subject_;
////
////	bool CheckAccess() const {
////		// Some real checks should go here.
////		std::cout << "Proxy: Checking access prior to firing a real request.\n";
////		return true;
////	}
////	void LogAccess() const {
////		std::cout << "Proxy: Logging the time of request.\n";
////	}
////
////	/**
////	 * The Proxy maintains a reference to an object of the RealSubject class. It
////	 * can be either lazy-loaded or passed to the Proxy by the client.
////	 */
////public:
////	Proxy(RealSubject* real_subject) : real_subject_(new RealSubject(*real_subject)) {
////	}
////
////	virtual~Proxy() {
////		delete real_subject_;
////	}
////	/**
////	 * The most common applications of the Proxy pattern are lazy loading,
////	 * caching, controlling the access, logging, etc. A Proxy can perform one of
////	 * these things and then, depending on the result, pass the execution to the
////	 * same method in a linked RealSubject object.
////	 */
////	void request() const  {
////		if (this->CheckAccess()) {
////			this->real_subject_->request();
////			this->LogAccess();
////		}
////	}
////};
/////**
//// * The client code is supposed to work with all objects (both subjects and
//// * proxies) via the Subject interface in order to support both real subjects and
//// * proxies. In real life, however, clients mostly work with their real subjects
//// * directly. In this case, to implement the pattern more easily, you can extend
//// * your proxy from the real subject's class.
//// */
////void ClientCode(const Subject& subject) {
////	// ...
////	subject.request();
////	// ...
////}
////
////int main()
////{
////	std::cout << "Client: Executing the client code with a real subject:\n";
////	RealSubject* real_subject = new RealSubject;
////	ClientCode(*real_subject);
////	std::cout << "\n";
////	std::cout << "Client: Executing the same client code with a proxy:\n";
////	Proxy* proxy = new Proxy(real_subject);
////	ClientCode(*proxy);
////
////	delete real_subject;
////	delete proxy;
////	return 0;
////
////	//ConcreteClass1* concreteClass1 = new ConcreteClass1;
////	//ClientCode(concreteClass1);
////
////	//Invoker* invoker = new Invoker;
////	//invoker->SetOnStart(new SimpleCommand("Say Hi!"));
////	//Receiver* receiver = new Receiver;
////	//invoker->SetOnFinish(new ComplexCommand(receiver, "Send email", "Save report"));
////	//invoker->DoSomethingImportant();
////
////	//delete invoker;
////	//delete receiver;
////
////	//ConcreteMediator* m = new ConcreteMediator();
////	//ConcreteColleague1* c1 = new ConcreteColleague1(m);
////	//ConcreteColleague2* c2 = new ConcreteColleague2(m);
////
////	//m->set(c1);
////	//m->set(c2);
////
////	//c1->Send("Hello");   // ConcreteColleague2 received: Hello
////	//c2->Send("World");  // ConcreteColleague1 received: World
////
////	//delete m;
////	//delete c1;
////	//delete c2;
////	//return 0;
////
////	////ConcretePrototypeA* conPro = new ConcretePrototypeA();
////	////conPro->clone();
////	//ChessPiece* black1, * black2, * black3, * white1, * white2;
////	//ChessPieceFactory* factory;
////
////	////获取享元工厂对象
////	//factory = ChessPieceFactory::getInstance();
////
////	////通过享元工厂获取三颗黑子
////	//black1 = factory->getChessPiece("b");
////	//black2 = factory->getChessPiece("b");
////	//black3 = factory->getChessPiece("b");
////	//std::cout << "两颗黑子是否相同：" << (black1 == black2) << std::endl;
////
////	////通过享元工厂获取两颗白子
////	//white1 = factory->getChessPiece("w");
////	//white2 = factory->getChessPiece("w");
////	//std::cout << "两颗白子是否相同：" << (white1 == white2) << std::endl;
////
////	//std::vector<Coordinates*> coordinates;
////	////std::function<Coordinates *(Coordinates *)> func = [&coordinates](Coordinates *coord ) {
////	//auto func = [&coordinates](Coordinates* coord) {
////	//	coordinates.push_back(coord);
////	//	return coord;
////	//};
////	////显示棋子
////	//black1->display(func(new Coordinates(1, 3)));
////	//black2->display(func(new Coordinates(2, 6)));;
////	//black3->display(func(new Coordinates(4, 7)));;
////	//white1->display(func(new Coordinates(5, 8)));;
////	//white2->display(func(new Coordinates(4, 1)));;
////
////	//for (auto& coordinate : coordinates) {
////	//	delete coordinate;
////	//}
////}
//
////#include <iostream>
////#define N 6
////#define maxT 1000
////int c[N][maxT] = { 0 };
////
////int Calculate_Max_Value(int v[N], int w[N], int i, int j)
////{
////	int temp = 0;
////	if (c[i][j] ==0){
////		return c[i][j];
////	}
////
////	if (i==0||j==0){
////		c[i][j] = 0;
////	}else {
////		c[i][j] = Calculate_Max_Value(v, w, i - 1, j);
////		if (i>0&&j>=w[i]){
////			temp = Calculate_Max_Value(v, w, i - 1, j-w[i])+v[i];
////			if (c[i][j]<temp){
////				c[i][j] = temp;
////			}
////		}
////	}
////
////	return c[i][j];
////
////}
////int Memoized_Knapsack(int v[N], int w[N], int t)
////{
////	int i;
////	int j;
////	for (i =0;i<N;i++){
////		for (j=0;j<=t;j++){
////			c[i][j] = -1;
////		}
////	}
////
////	return Calculate_Max_Value(v,w,N-1,t);
////}
////
////int main()
////{
////	int v[] = { 2,1,6,18,22,28 };
////	int w[] = { 3,1,2,5,6,7 };
////	int value = Memoized_Knapsack(v, w, 11);
////	std::cout << value << std::endl;
////}
////#include <iostream>
////#include <vector>
////class imp
////{
////public:
////	imp() = default;
////	virtual~imp() = default;
////	virtual void display() = 0;
////};
////
////class A:public imp
////{
////public:
////	A() = default;
////	~A() = default;
////	void display()
////	{
////		std::cout << "w_w" << std::endl;
////	}
////};
////
////class C:public A
////{
////public:
////	C() = default;
////	void dispalay(int a){
////		int value = 10;
////		int test_value = 100;
////	}
////
////	void display(float a)
////	{
////
////	}
////};
////
////class B:public imp
////{
////	class imp;
////public:
////	B() = default;
////	~B() = default;
////	void display()
////	{
////		std::cout << "w_w" << std::endl;
////	}
////};
////
////class D :public imp
////{
////public:
////	D() = default;
////	virtual ~D() = default;
////	virtual void display()
////	{
////		std::cout << "sw1" << std::endl;
////	}
////};
////
////
////int main()
////{
////	C ca;
////	ca.dispalay(1);
////
////	int a = 10;
////
////	imp* ptr = new A();
////	ptr->display();
////}
////
////#include <iostream>
////
////void selectionSort(int array[], int size)
////{
////	for (int i = 0;i < size - 1;i++) {
////		int min = i;
////		for (int j = i + 1;j < size;j++) {
////			if (array[j] < array[min]) {
////				min = j;
////			}
////		}
////
////		//将最小元素与无序序列第一个元素交换
////		int temp = array[min];
////		array[min] = array[i];
////		array[i] = temp;
////	}
////}
////
////void bubble_sort2(int* a, int len)
////{
////	int i, j;
////	for (i = 0;i < len - 1;i++) {
////		for (int j = 0;j < len - 1 - i;j++) {
////			//从大到小
////			if (a[j] < a[j+1]) {
////			//if (a[j] > a[j + 1]) {
////				int t = a[j];
////				a[j] = a[j + 1];
////				a[j + 1] = t;
////			}
////		}
////	}
////}
////
////int main()
////{
////	//int arr[] = {21,48,21,63,17 };
////	//int arr[] = { 6,4,3,2,5 };
////	int arr[] = { 10,20,12,11,5 };
////	int data_size = sizeof(arr)/sizeof(arr[0]);
////	bubble_sort2(arr, data_size);
////}
//
////#include <iostream>
////
////void display(int a, int b)
////{
////	if (a == 1) {
////		std::cout << "111" << std::endl;
////	}
////	else {
////		if (b == 2) {
////			std::cout << "222" << std::endl;
////		}
////		else {
////			std::cout << "333" << std::endl;
////		}
////	}
////
////}
////
////void shell_sort(int arr[], int len) {
////	int gap, i, j;
////	int temp;
////	for (gap = len >> 1; gap > 0; gap >>= 1)
////		for (i = gap; i < len; i++) {
////			temp = arr[i];
////			for (j = i - gap; j >= 0 && arr[j] > temp;j -= gap) {
////				arr[j + gap] = arr[j];
////			}
////
////			arr[j + gap] = temp;
////		}
////}
////
////////递增
//////void min_insert_sort(int arr[], int len)
//////{
//////	int i, j;
//////	for (i=1;i<len;i++){
//////		if (arr[i]<arr[i-1]){
//////			int temp = arr[i];
//////			for (j=i;arr[j-1]>temp&&j>0;j--){
//////				arr[j] = arr[j - 1];
//////			}
//////
//////			arr[j] = temp;
//////		}
//////	}
//////}
//////
////////递减
//////void max_insert_sort(int arr[], int len)
//////{
//////	int i, j;
//////	for (i = 1;i < len;i++) {
//////		if (arr[i] > arr[i - 1]) {
//////			int temp = arr[i];
//////			for (j = i;arr[j - 1] < temp && j > 0;j--) {
//////				arr[j] = arr[j - 1];
//////			}
//////
//////			arr[j] = temp;
//////		}
//////	}
//////}
////
//////void insert_sort(int arr[],int data_size)
//////{
//////	int i, j;
//////	for (i=1;i< data_size;i++){
//////		if (arr[i]<arr[i-1]){
//////			int temp = arr[i];
//////			for (j=i;arr[j-1]>temp && j>1;j--){
//////				arr[j] = arr[j - 1];
//////			}
//////
//////			arr[j] = temp;
//////		}
//////	}
//////}
////
////void insert_sort1(int arr[], int data_size)
////{
////	int i, j;
////	for (i = 1;i < data_size;i++) {
////		int temp = arr[i];
////		for (j = i;arr[j - 1] > temp && j > 1;j--) {
////			arr[j] = arr[j - 1];
////		}
////
////		arr[j] = temp;
////	}
////}
////
//////void shell_sort1(int arr[], int data_size)
//////{
//////	int grap,i, j;
//////	for (grap = data_size >>1;grap>0;grap=grap>>1){
//////		for (i = grap;i < data_size;i++) {
//////			int temp = arr[i];
//////			for (j = i-grap;arr[j] > temp && j >0;j-=grap) {
//////				arr[j+grap] = arr[j];
//////			}
//////
//////			arr[j+grap] = temp;
//////		}
//////	}
//////}
////
////void shell_sort1(int arr[], int data_size)
////{
////	int grap=0, i, j;
////	while (grap<data_size/3){
////		grap = grap * 3 + 1;
////	}
////
////	for (; grap > 0; grap /= 3) {
////		for (i = grap;i < data_size;i++) {
////			int temp = arr[i];
////			for (j = i - grap;arr[j] > temp && j > 0;j -= grap) {
////				arr[j + grap] = arr[j];
////			}
////
////			arr[j + grap] = temp;
////		}
////	}
////}
////
////int main()
////{
////	int arr[] = { 1,3,4,7,5,6 };
////	int data_size = sizeof(arr) / sizeof(arr[0]);
////	shell_sort1(arr, data_size);
////	//shell_sort1(arr, data_size);
////
////	//insert_sort1(arr, data_size);
////	//insert_sort(arr, data_size);
////	//max_insert_sort(arr, data_size);
////	//shell_sort(arr, data_size);
////	//display(1, 0);
////	//display(2,2);
////	//display(2,1);
////	display(2, 2);
////	display(1, 1);
////}
//
//#include <iostream>
//#include <vector>
//
////int str2int(const char* s)
////{
////	int val = 0;
////	while (*s) {
////		val = (val *10) + (*s - '0'); //将数字字符串转换为十进制整数
////		s++;
////	}
////
////	return val;
////}
//
////二分法查找(适用于数组,不适合于链表,查找的前提是必须顺序存储)
//
//int half_search(int arr[],int search_value,int data_size)
//{
//	int low = 0;
//	int high = data_size - 1;
//
//	while (low<high){
//		int mid = (low + high) / 2;
//		if (search_value == arr[mid]){
//			return mid;
//		}
//
//		if (search_value<arr[mid]){
//			high = mid - 1;
//		}
//
//		if (search_value>arr[mid]){
//			low = mid + 1;
//		}
//	}
//
//	return 0;
//}
//
//
//void merge_sort_recursive(int arr[], int reg[], int start, int end) {
//	if (start >= end)
//		return;
//	int len = end - start, mid = (len >> 1) + start;
//	int start1 = start, end1 = mid;
//	int start2 = mid + 1, end2 = end;
//	merge_sort_recursive(arr, reg, start1, end1);
//	merge_sort_recursive(arr, reg, start2, end2);
//	int k = start;
//	while (start1 <= end1 && start2 <= end2)
//		reg[k++] = arr[start1] < arr[start2] ? arr[start1++] : arr[start2++];
//	while (start1 <= end1)
//		reg[k++] = arr[start1++];
//	while (start2 <= end2)
//		reg[k++] = arr[start2++];
//	for (k = start; k <= end; k++)
//		arr[k] = reg[k];
//}
//
//void merge_sort(int arr[], const int len) {
//	int* reg = (int*)malloc(len * sizeof(arr[0]));
//	merge_sort_recursive(arr, reg, 0, len - 1);
//}
//
//void asc_count_sort(int* arr, int len) {
//	if (arr == nullptr){
//		return;
//	}
//
//	int min = arr[0], max = arr[0];
//	for (int i=1;i<len;++i){
//		if (arr[i]>max){
//			max = arr[i];
//		}
//
//		if (arr[i]<min){
//			min = arr[i];
//		}
//	}
//
//	//求出距离之差
//	int size = max - min + 1;
//	int* count_ptr = (int*)malloc(sizeof(arr[0]) * size);
//	memset(count_ptr, 0, sizeof(arr[0]) * size);
//	for (int i =0;i<len;++i){
//		//统计自己出现的次数
//		count_ptr[arr[i] - min]++;
//	}
//
//	//再进行,再进行，当前项和前一项相加,说白就是内部进行编号
//	for (int i =1;i<size;++i){
//		count_ptr[i] += count_ptr[i - 1];
//	}
//
//	int* psort = (int*)malloc(sizeof(arr[0]) * len);
//	memset(psort, 0, sizeof(arr[0]) * len);
//	//反向填充目标数组
//	for (int i=len-1;i>=0;i--){
//		count_ptr[arr[i] - min]--;
//		psort[count_ptr[arr[i] - min]] = arr[i];
//	}
//
//	for (int i = 0; i < len; i++) {
//		arr[i] = psort[i];
//	}
//
//	free(count_ptr);
//	free(psort);
//	count_ptr = NULL;
//	psort = NULL;
//}
//
//void min_heap_build(int arr[],int start,int end)
//{
//	int dad = start;
//	int son = 2 * dad+1;
//	while (son<=end){
//		if (son+1<=end && arr[son]>arr[son+1]){
//			son++;
//		}
//
//		if (arr[dad]<arr[son]){
//			return;
//		}
//
//		int temp = arr[son];
//		arr[son] = arr[dad];
//		arr[dad] = temp;
//		dad = son;
//		son = 2 * dad + 1;
//	}
//}
//
//void min_heap_sort(int arr[],int data_size)
//{
//	for (int index=data_size/2;index>=0;index--){
//		min_heap_build(arr, index, data_size - 1);
//	}
//
//	for (int index = data_size-1;index>=0;index--){
//		int temp = arr[0];
//		arr[0] = arr[index];
//		arr[index] = temp;
//		min_heap_build(arr,0,index-1);
//	}
//}
//
//int Median3(int* A, int left, int right) {
//	int center = (left + right) / 2;
//	if (A[left] > A[center]) {
//		int temp = A[left];
//		A[left] = A[center];
//		A[center] = A[temp];
//	}
//
//	if (A[left] > A[right]) {
//		int temp = A[left];
//		A[left] = A[right];
//		A[right] = A[temp];
//	}
//
//	if (A[center] > A[right]) {
//		int temp = A[center];
//		A[center] = A[right];
//		A[right] = A[temp];
//	}
//
//	int temp = A[center];	 //将基准Pivot藏到右边
//	A[center] = A[right];
//	A[right] = A[temp];
//
//	return A[right];
//}
//
////选取中间数位基准值
//void desc_quick_sort2(int src[], int begin, int end)
//{
//	if (begin > end) {
//		return;
//	}
//
//	int low = begin;
//	int high = end;
//
//	//右边为基准,左大右小
//	int base_value = Median3(src, low, high);
//
//	while (low < high) {
//		//先向左边搜索
//		while (low < high && src[low] > base_value) {
//			low++;
//		}
//		if (low < high) {
//			src[high] = src[low];
//			high--;
//		}
//
//		//向右边搜索
//		while (low < high && src[high] < base_value) {
//			high--;
//		}
//
//		if (low < high) {
//			src[low] = src[high];
//		}
//	}
//
//	//基准值回归
//	src[high] = base_value;
//	//向左边找
//	desc_quick_sort2(src, begin, high - 1);
//	//向右边找
//	desc_quick_sort2(src, high + 1, end);
//
//}
//void asc_bubble_sort(int arr[], int data_size)
//{
//	int i, j;
//	int count = 0;
//	for (i = 0;i < data_size;i++) {
//		for (j = 0;j < data_size - i - 1;++j) {
//			++count;
//			if (arr[j] > arr[j + 1]) {
//				int temp = arr[j];
//				arr[j] = arr[j + 1];
//				arr[j + 1] = temp;
//			}
//		}
//	}
//}
//
//void max_heap_build(int arr[], int start, int end)
//{
//	int parent_index = start;
//	int son_index = 2 * parent_index;
//	while (son_index<=end){
//		if (son_index+1<=end&&arr[son_index]<arr[son_index+1]){
//			++son_index;
//		}
//
//		if (arr[parent_index]>arr[son_index]){
//			break;
//		}
//
//		int temp = arr[son_index];
//		arr[son_index] = arr[parent_index];
//		arr[parent_index] = temp;
//		parent_index = son_index;
//		son_index = 2 * parent_index;
//	}
//}
//
//void min_heap_build1(int arr[], int start, int end)
//{
//	int dad = start;
//	int son = 2 * dad;
//	while (son <= end) {
//		if (son + 1 <= end && arr[son] > arr[son + 1]) {
//			son++;
//		}
//
//		if (arr[dad] < arr[son]) {
//			return;
//		}
//
//		int temp = arr[son];
//		arr[son] = arr[dad];
//		arr[dad] = temp;
//		dad = son;
//		son = 2 * dad;
//	}
//}
//
//void heap_sort(int arr[], int data_size)
//{
//	for (int i =data_size>>1;i>0;--i){
//		min_heap_build1(arr,i,data_size - 1);
//	}
//
//	for (int i =data_size-1;i>0;--i){
//		int temp = arr[1];
//		arr[1] = arr[i];
//		arr[i] = temp;
//
//		min_heap_build1(arr,1,i-1);
//	}
//
//}
//
//
//
//
//int main()
//{
//	//int arr[] = { 19,34,26,97,56,75};
//
//
//	std::vector<int> arr = { 6,5,1,4,7,8 };
//	
//
//	int data_size = sizeof(arr) / sizeof(arr[0]);
//	heap_sort(&arr[0], arr.size());
//	//asc_bubble_sort(arr, data_size);
//	//desc_quick_sort2(arr, 0, data_size - 1);
//	//QuickSort(arr, data_size);
//	//min_heap_sort(arr,data_size);
//	//merge_sort(arr, data_size);
//	int test_value =0;
//	//heap_sort(arr, data_size);
//	//min_heap_sort(arr, data_size-1);
//	//desc_quick_sort(arr,0,data_size-1);
//	//asc_insert_sort(arr, data_size);
//	//asc_bubble_sort(arr, data_size);
//	//desc_select_sort(arr, data_size);
//	//desc_shell_sort(arr, data_size);
//	//desc_insert_sort(arr, data_size);
//}


//#include <iostream>
//
//void max_heap_build(int arr[], int start, int end)
//{
//	int parent_index = start;
//	int son_index = 2 * parent_index;
//	while (son_index <= end) {
//		if (son_index + 1 <= end && arr[son_index] < arr[son_index + 1]) {
//			++son_index;
//		}
//
//		if (arr[parent_index] >=arr[son_index]) {
//			break;
//		}
//
//		int temp = arr[son_index];
//		arr[son_index] = arr[parent_index];
//		arr[parent_index] = temp;
//		parent_index = son_index;
//		son_index = 2 * parent_index;
//	}
//}
//
//void min_heap_build(int a[], int start, int end)
//{
//	int dad = start;
//	int son = 2 * dad;
//	while (son <= end) {
//		//先比较叶子节点
//		if (son + 1 <= end && a[son] > a[son + 1]) {
//			++son;
//		}
//
//		//然后再比较根节点
//		if (a[dad] <=a[son]) {
//			break;
//		}
//
//		int temp = a[son];
//		a[son] = a[dad];
//		a[dad] = temp;
//		dad = son;
//		son = 2 * dad;
//	}
//}
//
//void heap_sort(int arr[], int data_size)
//{
////	for (int i = data_size >> 1;i > 0;--i) {
////		//min_heap_build(arr, i-1, data_size - 1);
////		max_heap_build(arr, i - 1, data_size - 1);
////	}
////
////	for (int i = data_size - 1;i >0;--i) {
////		int temp = arr[0];
////		arr[0] = arr[i];
////		arr[i] = temp;
////
////		max_heap_build(arr, 0,i-1);
////		//min_heap_build(arr, 0, i - 1);
////	}
////
////}
////
////
////int main()
////{
////	int arr[] = { 97,34,26,19,56,75 };
////
////	int data_size = sizeof(arr) / sizeof(arr[0]);
////	heap_sort(arr, data_size);
////}
//
//#include <iostream>
//#include <string>
//#include <list>
//using namespace std;
//
//class Observer
//{
//public:
//	Observer() = default;
//	virtual ~Observer() = default;
//	virtual void Update() = 0;
//};
//
//
//class Blog
//{
//public:
//	Blog() {}
//	virtual ~Blog() {}
//	void Attach(Observer* observer) { m_observers.push_back(observer); }	 //添加观察者
//	void Remove(Observer* observer) { m_observers.remove(observer); }        //移除观察者
//	void Notify() //通知观察者
//	{
//		list<Observer*>::iterator iter = m_observers.begin();
//		for (; iter != m_observers.end(); iter++)
//			(*iter)->Update();
//	}
//	virtual void SetStatus(string s) { m_status = s; } //设置状态
//	virtual string GetStatus() { return m_status; }    //获得状态
//private:
//	list<Observer* > m_observers; //观察者链表
//protected:
//	string m_status; //状态
//};
//
//
//class BlogCSDN : public Blog
//{
//private:
//	string m_name; //博主名称
//public:
//	BlogCSDN(string name) : m_name(name) {}
//	~BlogCSDN() {}
//	void SetStatus(string s) { m_status = "通知回家 : " + m_name + s; } //具体设置状态信息
//	string GetStatus() { return m_status; }
//};
//
//class ObserverBlog :public Observer
//{
//public:
//	ObserverBlog(string name, Blog* blog) : m_name(name), m_blog(blog) {}
//	virtual ~ObserverBlog() = default;
//	void Update()
//	{
//		string status = m_blog->GetStatus();
//		cout << m_name << "-------" << status << endl;
//	}
//private:
//	string m_name;  //观察者名称
//	Blog* m_blog;   //观察的博客，当然以链表形式更好，就可以观察多个博客
//};
//
//int main()
//{
//	Blog* blog = new BlogCSDN("主角");
//	Observer* observer1 = new ObserverBlog("c++", blog);
//	Observer* observer2 = new ObserverBlog("java", blog);
//	Observer* observer3 = new ObserverBlog("c#", blog);
//	blog->Attach(observer1);
//	blog->Attach(observer2);
//	blog->Attach(observer3);
//	blog->SetStatus("吃饭啦");
//	blog->Notify();
//
//	delete blog; 
//	delete observer1;
//	return 0;
//}
//
//#include <iostream>
//#include <stdlib.h>
//using namespace std;
//
////结点类
//class Node {
//public:
//	int data;
//	Node* pNext;
//};
//
////单向循环链表类
//class CircularLinkList {
//public:
//	CircularLinkList() {
//		head = new Node;
//		head->data = -1;
//		head->pNext = head;
//	}
//	~CircularLinkList() { delete head; }
//	void CreateLinkList(int n);				//创建单向循环链表
//	void InsertNode(int position, int d);	//在指定位置插入结点
//	void TraverseLinkList();				//遍历链表
//	bool IsEmpty();							//判断链表是否为空
//	int GetLength();						//得到链表的长度
//	void DeleteNode(int position);			//删除指定位置结点
//	void DeleteLinkList();					//删除链表
//private:
//	Node* head;
//};
//
//void CircularLinkList::CreateLinkList(int n) {
//	if (n < 0) {
//		cout << "输入结点个数错误！" << endl;
//		exit(EXIT_FAILURE);
//	}
//	else {
//		Node* pnew, * ptemp = head;
//		int i = n;
//		while (n-- > 0) {
//			cout << "输入第" << i - n << "个结点值：";
//			pnew = new Node;
//			cin >> pnew->data;
//			pnew->pNext = head;
//			ptemp->pNext = pnew;
//			ptemp = pnew;
//		}
//	}
//}
//
//void CircularLinkList::InsertNode(int position, int d) {
//	if (position < 0 || position > GetLength() + 1) {
//		cout << "输入位置错误！" << endl;
//		exit(EXIT_FAILURE);
//	}
//	else {
//		Node* pnew, * ptemp = head;
//		pnew = new Node;
//		pnew->data = d;
//		while (position-- > 1)
//			ptemp = ptemp->pNext;
//		pnew->pNext = ptemp->pNext;
//		ptemp->pNext = pnew;
//	}
//}
//
//void CircularLinkList::TraverseLinkList() {
//	Node* ptemp = head->pNext;
//	while (ptemp != head) {
//		cout << ptemp->data << " ";
//		ptemp = ptemp->pNext;
//	}
//	cout << endl;
//}
//
//bool CircularLinkList::IsEmpty() {
//	if (head->pNext == head)
//		return true;
//	else
//		return false;
//}
//
//int CircularLinkList::GetLength() {
//	int n = 0;
//	Node* ptemp = head->pNext;
//	while (ptemp != head) {
//		n++;
//		ptemp = ptemp->pNext;
//	}
//	return n;
//}
//
//void CircularLinkList::DeleteNode(int position) {
//	if (position < 0 || position > GetLength()) {
//		cout << "输入位置错误！" << endl;
//		exit(EXIT_FAILURE);
//	}
//	else {
//		Node* ptemp = head, * pdelete;
//
//		while (position-- > 1)
//			ptemp = ptemp->pNext;
//		pdelete = ptemp->pNext;
//		ptemp->pNext = pdelete->pNext;
//		delete pdelete;
//		pdelete = NULL;
//	}
//}
//
//void CircularLinkList::DeleteLinkList() {
//	Node* pdelete = head->pNext, * ptemp;
//	while (pdelete != head) {
//		ptemp = pdelete->pNext;
//		head->pNext = ptemp;
//		delete pdelete;
//		pdelete = ptemp;
//	}
//}
//
//void swap(int& value1, int& value2)
//{
//	value1 ^= value2;
//	value2 ^= value1;
//	value1 ^= value2;
//}
//
//struct  A
//{
//	int a;
//	int b;
//};
//
//void display(A a)
//{
//
//}
//
////测试函数
//int main() {
//
//	int a = 1;
//	int b = 2;
//	swap(a, b);
//	CircularLinkList cl;
//	int position = 0, value = 0, n = 0;
//	bool flag = false;
//
//	cout << "请输入需要创建单向循环链表的结点个数：";
//	cin >> n;
//
//	cl.CreateLinkList(n);
//
//	cout << "打印链表值如下：";
//	cl.TraverseLinkList();
//
//	cout << "请输入插入结点的位置和值：";
//	cin >> position >> value;
//	cl.InsertNode(position, value);
//
//	cout << "打印链表值如下：";
//	cl.TraverseLinkList();
//
//	cout << "请输入要删除结点的位置：";
//	cin >> position;
//	cl.DeleteNode(position);
//
//	cout << "打印链表值如下：";
//	cl.TraverseLinkList();
//
//	cl.DeleteLinkList();
//	flag = cl.IsEmpty();
//	if (flag)
//		cout << "删除链表成功！" << endl;
//	else
//		cout << "删除链表失败！" << endl;
//
//	return 0;
//}
//

//#include <stdio.h>
//#include <iostream>
//using namespace std;
//// 队列的顺序存储结构(循环队列)
//#define MAX_QSIZE 5 // 最大队列长度+1
//typedef struct {
//	int* base; // 初始化的动态分配存储空间
//	int front; // 头指针，若队列不空，指向队列头元素
//	int rear; // 尾指针，若队列不空，指向队列尾元素的下一个位置
//} SqQueue;
//
//
//// 构造一个空队列Q
//SqQueue* Q_Init() {
//	SqQueue* Q = (SqQueue*)malloc(sizeof(SqQueue));
//	// 存储分配失败
//	if (!Q) {
//		exit(OVERFLOW);
//	}
//	Q->base = (int*)malloc(MAX_QSIZE * sizeof(int));
//	// 存储分配失败
//	if (!Q->base) {
//		exit(OVERFLOW);
//	}
//	Q->front = Q->rear = 0;
//	return Q;
//}
//
//// 销毁队列Q，Q不再存在
//void Q_Destroy(SqQueue* Q) {
//	if (Q->base)
//		free(Q->base);
//	Q->base = NULL;
//	Q->front = Q->rear = 0;
//	free(Q);
//}

// 将Q清为空队列
//void Q_Clear(SqQueue* Q) {
//	Q->front = Q->rear = 0;
//}
//
//// 若队列Q为空队列，则返回1；否则返回-1
//int Q_Empty(SqQueue Q) {
//	if (Q.front == Q.rear) // 队列空的标志
//		return 1;
//	else
//		return -1;
//}
//
//// 返回Q的元素个数，即队列的长度
//int Q_Length(SqQueue Q) {
//	return (Q.rear - Q.front + MAX_QSIZE) % MAX_QSIZE;
//}
//
//// 若队列不空，则用e返回Q的队头元素，并返回OK；否则返回ERROR
//int Q_GetHead(SqQueue Q, int& e) {
//	if (Q.front == Q.rear) // 队列空
//		return -1;
//	e = Q.base[Q.front];
//	return 1;
//}
//
//// 打印队列中的内容
//void Q_Print(SqQueue Q) {
//	int p = Q.front;
//	while (Q.rear != p) {
//		cout << Q.base[p] << endl;
//		p = (p + 1) % MAX_QSIZE;
//	}
//}
//
//// 插入元素e为Q的新的队尾元素
//int Q_Put(SqQueue* Q, int e) {
//	if ((Q->rear + 1) % MAX_QSIZE == Q->front) // 队列满
//		return -1;
//	Q->base[Q->rear] = e;
//	Q->rear = (Q->rear + 1) % MAX_QSIZE;
//	return 1;
//}
//
//// 若队列不空，则删除Q的队头元素，用e返回其值，并返回1；否则返回-1
//int Q_Poll(SqQueue* Q, int& e) {
//	if (Q->front == Q->rear) // 队列空
//		return -1;
//	e = Q->base[Q->front];
//	Q->front = (Q->front + 1) % MAX_QSIZE;
//	return 1;
//}
//
//int main()
//{
//	SqQueue* ptr = Q_Init();
//
//	Q_Put(ptr, 1);
//	Q_Put(ptr, 2);
//	Q_Put(ptr, 3);
//	Q_Put(ptr, 4);
//
//	int len = Q_Length(*ptr);
//}
//#include <stdio.h>
//#include <math.h>
//#define n 4
//int queen[n + 1];
//void Show() {     /* 输出所有皇后摆放方案 */
//	int i;
//	printf("(");
//	for (i = 1;i <= n;i++) {
//		printf(" %d", queen[i]);
//	}
//	printf(")\n");
//}
//
//int Place(int j)
//{
//	for (int i = 1; i < j; i++)
//	{
//		if (queen[i] == queen[j] || abs(queen[i] - queen[j]) == (j - i)) {
//			return 0;
//		}
//	}
//
//	return 1;
//}
//
//void Nqueen(int j)
//{
//	for (int i = 1; i <= n; i++)
//	{
//		queen[j] = i;
//		if (Place(j)) {
//			if (j == n) {
//				Show();
//			}
//			else {
//				Nqueen(j + 1);
//			}
//		}
//	}
//}
//
//int main() {
//	Nqueen(1);
//	return 0;
//}

//#include <string>
//#include <iostream>
//#include <vector>
//#include <string>
//using namespace std;
//
////求三个数的最小值
//int min(int a, int b, int c) {
//	if (a > b) {
//		if (b > c)
//			return c;
//		else
//			return b;
//	}
//	if (a > c) {
//		if (c > b)
//			return b;
//		else
//			return c;
//	}
//	if (b > c) {
//		if (c > a)
//			return a;
//		else
//			return c;
//	}
//}
//
////使用动态规划求解方法
//int StringDistance(string& str1, int start1, int end1,
//	string& str2, int start2, int end2) {
//	if (start1 > end1) {
//		if (start2 > end2)
//			return 0;
//		else
//			return end2 - start2 + 1;
//	}
//
//	if (start2 > end2) {
//		if (start1 > end1)
//			return 0;
//		else
//			return end1 - start1 + 1;
//	}
//
//	if (str1[start1] == str2[start2])
//		return StringDistance(str1, start1 + 1, end1, str2, start2 + 1, end2);
//	else {
//		int t1 = StringDistance(str1, start1 + 1, end1, str2, start2, end2);
//		int t2 = StringDistance(str1, start1, end1, str2, start2 + 1, end2);
//		int t3 = StringDistance(str1, start1 + 1, end1, str2, start2 + 1, end2);
//		return min(t1, t2, t3) + 1;
//	}
//}
//
////递归求解方法
//int StringDistance(string& str1, string& str2) {
//	int len1 = str1.length(), len2 = str2.length();
//	vector<vector<int> > ivec(len1 + 1, vector<int>(len2 + 1));
//
//	//下面初始化的含义：
//	//当str1长度为0时，那么两个字符串的距离就是str2的长度
//	//同样，当str2长度为0， 那么两个字符串距离就是str1的长度
//	for (int i = 0; i < len1 + 1; ++i)
//		ivec[i][0] = i;
//	for (int i = 0; i < len2 + 1; ++i)
//		ivec[0][i] = i;
//
//	for (int i = 1; i <= len1; ++i) {
//		for (int j = 1; j <= len2; ++j) {
//			if (str1[i - 1] == str2[j - 1])
//				ivec[i][j] = ivec[i - 1][j - 1];
//			else
//				ivec[i][j] = min(ivec[i][j - 1], ivec[i - 1][j], ivec[i - 1][j - 1]) + 1;
//		}
//	}
//	return ivec[len1][len2];
//}
//int main() {
//	string str1="abc", str2="abe";
//	//int dis = StringDistance(str1, 0, str1.length() - 1,	str2, 0, str2.length() - 1);
//	int dis = StringDistance(str1, str2);
//	cout << dis << endl;
//}

//#include <iostream>
//
//void fun(int n) {
//	int count = 0;
//	while ((count +1) * (count + 1) <= n) {
//		count++;
//	}
//}
//
//
//void add(int& a, int n)
//{
//	for (int i =1;i<=n;i++){
//		a++;
//		add(a, n - i);
//	}
//
//}
//
////设该语句共执行了 t次，则2t+1=n/2，故t=log2(n/2)-1=log2n-2，得 T(n)=O(log2n)。
//void add(int n)
//{
//	int i = 0;
//	for (int i =0;i<n;++i){
//		while (i <= n) {
//			i = i * 3;
//		}
//	}
//}
//
//int main()
//{
//	fun(25);
//	int sum = 0;
//	add(sum,3);
//	//add(27);
//}


//#include <iostream>
//#include <vector>
//#include <string>
//#include <unordered_set>
//
////第N个泰波那契数(N-th Tribonacci Number)
//int tribonacci(int n) {
//	std::vector<int>dp;
//	dp.resize(n + 1);
//	dp[0] = 0;
//	for (int i =1;i<3;++i){
//		dp[i]++;
//	}
//
//	for (int i=3;i<=n;++i){
//		dp[i] = dp[i - 1] + dp[i - 2]+dp[i-3];
//	}
//
//	return dp[n];
//}
//
//bool wordBreak(std::string str,std::vector<std::string>& wordDict) {
//	std::unordered_set<std::string> wordSet(wordDict.begin(), wordDict.end());
//	std::vector<bool> dp(str.size() + 1, false);
//	dp[0] = true;
//
//	for (int i = 1; i <= str.size(); ++i) {
//		for (int j = 0; j < i; ++j) {
//			std::string word = str.substr(j, i - j);
//			if (wordSet.find(word) != wordSet.end() && dp[j]) {
//				dp[i] = true;
//			}
//		}
//	}
//	return dp[str.size()];
//}
//
//int main() {
//	int value = tribonacci(25);
//}
//#include <stdio.h>
//#include <conio.h>
//
//int n = 5;//物品数量
//int max_w = 11;//背包容量
//int v[] = { 1,6,18,22,28 };//各个物品的价值
//int w[] = { 1,2,5,6,7 };//各个物品的重量
//int curren_w = 0;//当前背包重量
//int current_v = 0;//当前背包中物品价值
//int best_value = 0;  //最优值；当前的最大价值，初始化为0  
//
////递归
//void brack_track(int index)
//{
//	if (index>n-1){
//		if (current_v>best_value){
//			//保存更优的值和解  
//			best_value = current_v;
//		}
//
//		return;
//	}
//
//	//约束条件：放的下  
//	if ((curren_w + w[index]) <= max_w)
//	{
//		curren_w += w[index];
//		current_v += v[index];
//		brack_track(index + 1);
//		curren_w -= w[index];
//		current_v -= v[index];
//	}
//
//	brack_track(index + 1);
//}
//
//void brack_track(int i, int tw, int tv)
//{
//	if (i > n - 1)   //找到一个叶子结点
//	{
//		if (tw == max_w && tv > best_value)  //找到一个最优解
//		{
//			best_value = tv;
//		}
//
//		return;
//	}
//
//	//试探求解
//	if (tw+w[i]<=max_w){
//		brack_track(i + 1, tw + w[i], tv + v[i]);
//	}
//
//	brack_track(i + 1, tw, tv);
//}
//
//int main()
//{
//	brack_track(0,0,0);
//	printf("最有价值为：%d\n", best_value);
//
//	return 0;
//}


//#include<stdio.h> 
//#define N 4  
//int cc,//当前路径费用        
//bestc;//当前最优解费用  
//int a[N + 1][N + 1];//邻接矩阵，存放图的信息 
//int bestx[N + 1];//当前最优解 
//int x[N + 1];//当前解 
//void inputAjac()
//{
//	int i, j;
//	printf("输入大于0的值表示有边,小于0表示无边：\n");
//	for (i = 1;i <= N;i++)
//	{
//		for (j = i + 1;j <= N;j++)
//		{
//			printf("请输入第%d个城市到第%d个城市所需路费为：", i, j);
//			scanf("%d", &a[i][j]);
//			a[j][i] = a[i][j];
//		}
//	}
//}
//void backtrack(int i)
//{
//	if (i == N)
//	{
//		if (a[x[N - 1]][x[N]] > 0 && a[x[N]][x[1]] > 0)
//		{
//			if (bestc<0 || bestc>cc + a[x[N - 1]][x[N]] + a[x[N]][x[1]])
//			{
//				int j;
//				for (j = 1;j <= N;j++)
//				{
//					bestx[j] = x[j];
//					bestc = cc + a[x[N - 1]][x[N]] + a[x[N]][x[1]];
//				}
//			}
//		}
//	}
//	else
//	{
//		int j;
//		for (j = i;j <= N;j++)
//		{
//			if (a[x[i - 1]][x[j]] > 0)
//			{
//				if (bestc<0 || bestc>cc + a[x[i - 1]][x[j]] + a[x[j]][x[1]])
//				{
//					int temp;
//					cc += a[x[i - 1]][x[j]];
//					temp = x[i];
//					x[i] = x[j];
//					x[j] = temp;
//					backtrack(i + 1);
//					temp = x[i];
//					x[i] = x[j];
//					x[j] = temp;
//					cc -= a[x[i - 1]][x[j]];
//				}
//			}
//		}
//	}
//}
//int tsp()
//{
//	//初始化  
//	int i;
//	for (i = 1;i <= N;i++)
//	{
//		x[i] = i;
//	}
//	cc = 0, bestc = -1;
//	inputAjac();
//	backtrack(2);
//	return bestc;
//}
//
//void output()
//{
//	int i;
//	for (i = 1;i <= N;i++)
//	{
//		printf("%4d", bestx[i]);
//	}
//	printf("%4d", bestx[1]);
//	printf("\n");
//}
//
//void test()
//{
//	int value = 10;
//}
//
//void main()
//{
//	printf("走%d个城市最少路费为：%d", N, tsp());
//	printf("\n");
//	printf("走法为:");
//	output();
//}


#include <iostream>

//归并排序
int *data_ptr = nullptr;
void asc_merge(int arr[], int low, int mid, int high)
{
	int i, j, k;
	//先拷贝数组元素
	for (i = low;i <= high;i++) {
		data_ptr[i] = arr[i];
	}

	//两两比较，进行合并
	i = low;
	j = mid + 1;
	//k是控制数组的下标
	for (k = low;i <= mid && j <= high;k++) {
		(data_ptr[i] <= data_ptr[j]) ? arr[k] =
			data_ptr[i++] : arr[k] = data_ptr[j++];
	}

	//扫尾工作
	while (i <= mid) {
		arr[k++] = data_ptr[i++];
	}

	while (j <= high) {
		arr[k++] = data_ptr[j++];
	}

}

void asc_merge_sort(int arr[], int low, int high)
{
	if (low == high) {
		return;
	}

	//二路分组
	int mid = (low + high) / 2;
	asc_merge_sort(arr, low, mid);//向左半区进行划分
	asc_merge_sort(arr, mid + 1, high);//向右半区进行划分
	asc_merge(arr, low, mid, high);//合并所有分路
}

class A
{
  friend void display();
public:
	A():a_(100){

	}
	~A() = default;
private:
	int a_;
};

void display()
{
	A a;
	
	std::cout << a.a_ << std::endl;
}

int main()
{
	int8_t a = -2;
	int8_t b = a >> 1;
	display();
	float f = 1.5678e3;

	float ff = (float)(double)f;
	int arr[] = { 1,3,4,2,5,6 };
	int data_size = sizeof(arr) / sizeof(arr[0]);
	data_ptr = (int*)malloc(data_size * sizeof(int));

	asc_merge_sort(arr, 0, data_size - 1);
	delete data_ptr;
	data_ptr = nullptr;
}
