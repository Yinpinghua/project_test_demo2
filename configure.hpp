#ifndef configure_h__
#define configure_h__

#include "serialize.hpp"

template<typename T>
class configure {
public:
	static configure& instance() {
		static configure instance;
		return instance;
	}

	auto get_parse_result() {
		return result_;
	}

	bool parse_conf(const std::string& file_path) {
		if (!fs::exists(file_path)) {
			return false;
		}

		std::ifstream file(file_path, std::ios::binary | std::ios::ate);
		if (!file.is_open()) {
			return false;
		}

		std::string data;
		std::size_t size = file.tellg();
		data.resize(size);
		file.seekg(0, std::ios::beg);

		file.read(&data[0], size);
		file.close();
		return serialization::from_json(result_, data.data(), size);
	}

	bool persist_conf(const std::string& file_path, T&& value) {
		str_stream::string_stream ss;
		serialization::to_json(ss, std::forward<T&&>(value));
		std::ofstream out_file(file_path, std::ios::binary);
		if (!out_file.is_open()) {
			return false;
		}

		out_file.write(ss.str().data(), ss.str().size());
		out_file.close();
		return true;
	}

private:
	configure() = default;
	configure(const configure&) = delete;
	configure& operator==(const configure&) = delete;
	configure(const configure&&) = delete;
	configure& operator==(const configure&&) = delete;
private:
	T result_;
}


#endif // configure_h__
