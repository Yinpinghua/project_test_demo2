#ifndef stream_format_h__
#define stream_format_h__

#include "msg.h"
#include <vector>

class stream_format
{
public:
	stream_format() = default;
	virtual ~stream_format() = default;
	uint16_t get_header_size()const {
		return header_size_;
	}

	uint16_t get_cmd_offset()const {
		return packet_cmd_offset_;
	}

	uint16_t get_body_size_offset()const {
		return packet_body_size_offset_;
	}
	virtual void write_header(Cmd_size cmd){

	}

	virtual void write_body(const char* str, std::size_t data_size)
	{

	}
private:
	uint16_t header_size_ = HEADER_OFFSET;
	uint16_t packet_cmd_offset_ = CMD_OFFSET;
	uint16_t packet_body_size_offset_ = BODY_OFFSET;
};

class write_tream_format :public stream_format
{
public:
	write_tream_format() {
		datas_.resize(get_header_size());
	}

	std::vector<char>get_send_data(){
		return std::move(datas_);
	}

	virtual ~write_tream_format() = default;
	virtual void write_header(Cmd_size cmd){
		write(reinterpret_cast<const char*>(&cmd),sizeof(cmd), get_cmd_offset());
	}

	virtual void write_body(const char* str, size_t data_size){
		datas_.resize(static_cast<size_t>(HEADER_OFFSET+data_size));
		write(reinterpret_cast<const char*>(&data_size), sizeof(Body_Size), get_body_size_offset());
		memcpy(&datas_[0] + HEADER_OFFSET, str, data_size);
	}
private:
	void write(const char* buffer, std::size_t size, std::size_t write_pos) {
		memcpy(&datas_[0] + write_pos, buffer, size);
	}
private:
	std::size_t write_pos_ = 0;
	std::vector<char>datas_;
};

#endif // stream_format_h__
