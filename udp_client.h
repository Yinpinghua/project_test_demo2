#ifndef udp_client_h__
#define udp_client_h__
#include <string>
#include <boost/asio.hpp>

class udp_client
{
public:
	udp_client();
	~udp_client();
	void connect(const uint16_t port);
	bool send_msg(const char* buf, size_t len);
	size_t recv_msg();
	void get_data(char* buff, size_t len);
	void close_socket();
private:
	std::vector<char>recv_buffers_;
	std::vector<char>send_buffers_;
	boost::asio::io_context ios_;
	boost::asio::ip::udp::socket socket_;
	boost::asio::ip::udp::endpoint remote_endpoint_;
};
#endif // udp_client_h__
