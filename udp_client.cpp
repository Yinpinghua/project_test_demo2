
#include "udp_client.h"

udp_client::udp_client()
	:socket_(ios_,
		boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 0))
{

}

udp_client::~udp_client()
{
	close_socket();
}

void udp_client::connect(const uint16_t port)
{
	remote_endpoint_ = 
		boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), port);
}

bool udp_client::send_msg(const char* buf, size_t len)
{
	send_buffers_.clear();
	send_buffers_.resize(len);
	memcpy(&send_buffers_[0], buf, len);
	boost::system::error_code ec;
	socket_.send_to(boost::asio::buffer(send_buffers_, len), remote_endpoint_,0,ec);
	if (ec){
		return false;

	}

	return true;
}

size_t udp_client::recv_msg()
{
	recv_buffers_.clear();
	recv_buffers_.resize(64 * 1024);
	boost::system::error_code ec;
	size_t len = socket_.receive_from(boost::asio::buffer(recv_buffers_,recv_buffers_.size()),
		remote_endpoint_,0,ec);
	if (ec){
		return 0;
	}

	return len;
}

void udp_client::get_data(char* buff, size_t len)
{
	std::string temp_str;
	temp_str.resize(len);
	memcpy(&temp_str[0],&recv_buffers_[0], len);
	memcpy(buff, temp_str.c_str(), len);
}

void udp_client::close_socket()
{
	if (!socket_.is_open()){
		return;
	}

	boost::system::error_code ec;
	socket_.close(ec);
}

