#include "detect_session.h"
#include "ssl_http_session.h"
#include "plain_http_session.h"

detect_session::detect_session(tcp::socket&& socket, ssl::context& ctx)
	: stream_(std::move(socket))
	, ctx_(ctx)
{

}

void detect_session::run()
{
	// We need to be executing within a strand to perform async operations
// on the I/O objects in this session. Although not strictly necessary
// for single-threaded contexts, this example code is written to be
// thread-safe by default.
	net::dispatch(
		stream_.get_executor(),
		beast::bind_front_handler(
			&detect_session::on_run,
			this->shared_from_this()));
}

void detect_session::on_run()
{
	// Set the timeout.
	stream_.expires_after(std::chrono::seconds(30));

	beast::async_detect_ssl(
		stream_,
		buffer_,
		beast::bind_front_handler(
			&detect_session::on_detect,
			this->shared_from_this()));
}

void detect_session::on_detect(beast::error_code ec, bool result)
{
	if (ec) {
		return fail(ec, "detect");
	}

	if (result) {
		// Launch SSL session
		std::make_shared<ssl_http_session>(
			std::move(stream_),
			ctx_,
			std::move(buffer_))->run();
		return;
	}

	// Launch plain session
	std::make_shared<plain_http_session>(
		std::move(stream_),
		std::move(buffer_))->run();
}

