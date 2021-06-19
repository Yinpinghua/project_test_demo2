#ifndef ipdb_h__
#define ipdb_h__

/*****************************************************************************************************/
/****************此ip库只支持ipv4格式,不支持ipv6*****************************************************/
/****************************************************************************************************/

#include <memory>
#include <iostream>
#include <vector>
#include <map>
#include <sstream>
#include <unordered_map>
#include <fstream>
#include <boost/locale.hpp>
#include <boost/filesystem.hpp>
#include "nlohmann_json.hpp"
#ifdef _WIN32
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

constexpr uint16_t g_ipv4_version = 0x01;
constexpr uint16_t g_ipv6_version = 0x02;
constexpr int g_ipv4_bit = 32;
constexpr int g_ipv6_bit = 128;


//长整型转大小端
constexpr std::uint32_t little_swap32(std::uint32_t value) {
	return ((value & 0xff000000) >> 24) |
		((value & 0x00ff0000) >> 8) |
		((value & 0x0000ff00) << 8) |
		((value & 0x000000ff) << 24);
}

std::vector<std::string> split(const std::string& s, const std::string& sp) {
	std::vector<std::string> output;

	std::string::size_type prev_pos = 0, pos = 0;

	while ((pos = s.find(sp, pos)) != std::string::npos) {
		std::string substring(s.substr(prev_pos, pos - prev_pos));

		output.emplace_back(substring);

		prev_pos = ++pos;
	}

	output.emplace_back(s.substr(prev_pos, pos - prev_pos)); // Last word

	return std::move(output);
}

bool is_valid_utf8(const char* string)
{
	if (string == nullptr ||
		strlen(string) == 0) {
		return false;
	}

	const unsigned char* bytes = (const unsigned char*)string;
	unsigned int cp = 0;
	int num = 0;

	while (*bytes != 0x00) {
		if ((*bytes & 0x80) == 0x00) {
			// U+0000 to U+007F 
			cp = (*bytes & 0x7F);
			num = 1;
		}
		else if ((*bytes & 0xE0) == 0xC0) {
			// U+0080 to U+07FF 
			cp = (*bytes & 0x1F);
			num = 2;
		}
		else if ((*bytes & 0xF0) == 0xE0) {
			// U+0800 to U+FFFF 
			cp = (*bytes & 0x0F);
			num = 3;
		}
		else if ((*bytes & 0xF8) == 0xF0) {
			// U+10000 to U+10FFFF 
			cp = (*bytes & 0x07);
			num = 4;
		}
		else {
			return false;
		}

		bytes += 1;
		for (int i = 1; i < num; ++i) {
			if ((*bytes & 0xC0) != 0x80)
				return false;
			cp = (cp << 6) | (*bytes & 0x3F);
			bytes += 1;
		}

		if ((cp > 0x10FFFF) ||
			((cp >= 0xD800) && (cp <= 0xDFFF)) ||
			((cp <= 0x007F) && (num != 1)) ||
			((cp >= 0x0080) && (cp <= 0x07FF) && (num != 2)) ||
			((cp >= 0x0800) && (cp <= 0xFFFF) && (num != 3)) ||
			((cp >= 0x10000) && (cp <= 0x1FFFFF) && (num != 4))) {
			return false;
		}
	}

	return true;
}


class reader
{
public:
	explicit reader(const std::string& file) {
		std::ifstream fs(file, std::ios::binary | std::ios::ate);
		if (!fs.is_open()) {
			std::cout << "ipdb file not exist" << std::endl;
			return;
		}

		file_size_ = fs.tellg();
		uint32_t meta_length = 0;
		fs.seekg(0, std::ios::beg);
		fs.read((char*)&meta_length, 4);
		meta_length = htonl(meta_length);
		std::string json_str;
		json_str.resize(meta_length);
		fs.read(&json_str[0], meta_length);

		if (!parse_json(json_str)) {
			std::cout << "ipdb json parse error" << std::endl;
			return;
		}

		if (file_size_ != (4 + meta_length + total_size_)) {
			std::cout << "ipdb file size error" << std::endl;
			return;
		}

		auto data_len = file_size_ - 4 - meta_length;
		data_.resize(data_len);
		fs.read(&data_[0], data_len);
		data_size_ = data_len;
		auto node = 0;
		for (auto i = 0; i < 96 && node < node_count_; ++i) {
			if (i >= 80) {
				node = read_node(node, 1);
			}
			else {
				node = read_node(node, 0);
			}
		}
		v4_offset_ = node;

		fs.close();
	}

	virtual ~reader() {
		data_.clear();
		fields_.clear();
		languages_.clear();
	}

	std::vector<std::string> find(const std::string& addr, const std::string& language) {
		return finds(addr, language);
	}

	std::map<std::string, std::string> find_map(const std::string& addr, const std::string& language) {
		std::map<std::string, std::string> info;
		auto data = finds(addr, language);
		if (data.size() == 0 || fields_.size() == 0) {
			return std::move(info);
		}

		auto k = 0;
		for (auto& v : data) {
			info.emplace(fields_[k++], std::move(v));
		}

		return std::move(info);
	}

	bool is_ipv4_support() {
		return (ip_version_ & g_ipv4_version) == g_ipv4_version;
	}

	bool is_ipv6_support() {
		return (ip_version_ & g_ipv6_version) == g_ipv6_version;
	}

	uint64_t build_time() {
		return build_;
	}
private:
	bool parse_json(const std::string& json_str) {
		std::cout << json_str.c_str() << std::endl;
		try {
			auto json = nlohmann::json::parse(json_str.c_str());
			build_ = json.value("build", 0);
			ip_version_ = json.value("ip_version", 3);
			node_count_ = json.value("node_count", -1);
			total_size_ = json.value("total_size", -1);

			if (node_count_ == -1 || total_size_ == -1) {
				return false;
			}

			auto json_arr = nlohmann::json::array();

			json_arr = json.value("fields", std::move(json_arr));
			for (auto& var : json_arr) {
				fields_.push_back(std::move(var.get<std::string>()));
			}

			nlohmann::json js;
			js = json.value("languages", std::move(js));
			int cn = js.value("CN", -1);
			int en = js.value("EN", -1);

			if (cn == 0) {
				languages_.emplace("CN", cn);
				return true;
			}

			if (en == 0) {
				languages_.emplace("EN", en);
				return true;
			}

			return false;
		}
		catch (...) {
			std::cout << "ipdb json error"<<std::endl;
			return false;
		}

		return true;
	}

	int read_node(int node, int index) const {
		auto off = node * 8 + index * 4;
		return ntohl(static_cast<uint32_t>(*(int*)&data_[off]));
	}

	std::string resolve(int node) {
		std::string bytes;
		if (node <= 0 || data_.size() == 0) {
			std::cout << "ipdb data error" << std::endl;
			return std::move(bytes);
		}

		auto resolved = node - node_count_ + node_count_ * 8;
		if (resolved >= file_size_) {
			return std::move(bytes);
		}

		auto size = (data_[resolved] << 8) | data_[resolved + 2];
		if ((resolved + 2 + size) > data_size_) {
			return std::move(bytes);
		}

		bytes = std::string((&data_[resolved + 2]));
		return std::move(bytes);
	}

	int search(const u_char* ip, int bit_count) const {
		int node = 0;

		if (bit_count == 32) {
			node = v4_offset_;
		}

		for (auto i = 0; i < bit_count; ++i) {
			if (node > node_count_) {
				break;
			}

			node = read_node(node, ((0xFF & int(ip[i >> 3])) >> uint32_t(7 - (i % 8))) & 1);
		}

		if (node > node_count_) {
			return node;
		}

		std::cout<< "ipdb data error"<<std::endl;
		return node;
	}

	std::string find_str(const std::string& addr) {
		int node = 0;
		std::string str;
		struct in_addr addr4 {};
		struct in6_addr addr6 {};
		if (inet_pton(AF_INET, addr.c_str(), &addr4)) {
			if (!is_ipv4_support()) {
				std::cout << "not support ipv4" << std::endl;
				return std::move(str);
			}

			node = search((const u_char*)&addr4.s_addr, g_ipv4_bit);
		}
		else if (inet_pton(AF_INET6, addr.c_str(), &addr6)) {
			if (!is_ipv6_support()) {
				std::cout << "not support ipv6" << std::endl;
				return std::move(str);
			}

			node = search((const u_char*)&addr6.s6_addr, g_ipv6_bit);
		}
		else {
			std::cout << "ip format error" << std::endl;
			return std::move(str);
		}

		return  resolve(node);
	}

	std::vector<std::string> finds(const std::string& addr, const std::string& language) {
		std::vector<std::string> result;

		auto iter_find = languages_.find(language);
		if (iter_find == languages_.end()) {
			std::cout << "not support language:" << language << std::endl;;
			return std::move(result);
		}

		auto off = iter_find->second;

		auto body = find_str(addr);
		if (body.empty()) {
			std::cout << "ipdb data error" << language << std::endl;;
			return std::move(result);
		}

		auto tmp = split(body, "\t");

		if (off + fields_.size() > tmp.size()) {
			std::cout << "ipdb data error" << std::endl;
			return std::move(result);
		}

		for (auto i = tmp.begin() + off; i != tmp.begin() + off + fields_.size(); ++i) {
			result.push_back(std::move(*i));
		}

		return std::move(result);
	}
private:
	uint16_t ip_version_{};                     //`json:"ip_version"`
	int v4_offset_ = 0;
	size_t file_size_ = 0;
	size_t data_size_ = 0;
	int node_count_{};                          //`json:"node_count"`
	int total_size_{};                          //`json:"total_size"`
	uint64_t build_{};                          //`json:"build"`
	std::string data_;
	std::unordered_map<std::string, int> languages_;      //`json:"languages"`
	std::vector<std::string> fields_;          //`json:"fields"`
};

class city_info
{
public:
	explicit city_info(const std::vector<std::string>& data) {
		data_ = data;
	}
	~city_info() = default;

	std::string str() {
		std::stringstream sb;
		sb << "country_name:";
		sb << country_name();
		sb << "\n";
		sb << "region_name:";
		sb << region_name();
		sb << "\n";
		sb << "city_name:";
		sb << city_name();
		sb << "\n";
		sb << "owner_domain:";
		sb << owner_domain();
		sb << "\n";
		sb << "isp_domain:";
		sb << is_pDomain();
		sb << "\n";
		sb << "latitude:";
		sb << latitude();
		sb << "\n";
		sb << "longitude:";
		sb << longitude();
		sb << "\n";

		sb << "timezone:";
		sb << timezone();
		sb << "\n";

		sb << "utc_offset:";
		sb << utc_offset();
		sb << "\n";

		sb << "china_admin_code:";
		sb << china_admin_code();
		sb << "\n";

		sb << "idd_code:";
		sb << idd_code();
		sb << "\n";

		sb << "country_code:";
		sb << country_code();
		sb << "\n";

		sb << "continent_code:";
		sb << continent_code();
		sb << "\n";

		sb << "idc:";
		sb << idc();
		sb << "\n";

		sb << "base_station:";
		sb << base_station();
		sb << "\n";

		sb << "country_code3:";
		sb << country_code3();
		sb << "\n";

		sb << "european_union:";
		sb << european_union();
		sb << "\n";

		sb << "currency_code:";
		sb << currency_code();
		sb << "\n";

		sb << "currency_name:";
		sb << currency_name();
		sb << "\n";

		sb << "anycast:";
		sb << anycast();

		return std::move(sb.str());
	}
private:
	std::string country_name() {
		std::string temp_str;
		if (!data_.empty()) {
			temp_str = data_[0];
		}

		return std::move(temp_str);
	}

	std::string region_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 2) {
			temp_str = data_[1];
		}

		return std::move(temp_str);
	}

	std::string city_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 3) {
			temp_str = data_[2];
		}

		return std::move(temp_str);
	}

	std::string owner_domain() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 4) {
			temp_str = data_[3];
		}

		return std::move(temp_str);
	}

	std::string is_pDomain() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 5) {
			temp_str = data_[4];
		}

		return std::move(temp_str);
	}

	std::string latitude() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 6) {
			temp_str = data_[5];
		}

		return std::move(temp_str);
	}

	std::string longitude() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 7) {
			temp_str = data_[6];
		}

		return std::move(temp_str);
	}

	std::string timezone() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 8) {
			temp_str = data_[7];
		}

		return std::move(temp_str);
	}

	std::string utc_offset() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 9) {
			temp_str = data_[8];
		}

		return std::move(temp_str);
	}

	std::string china_admin_code() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 10) {
			temp_str = data_[9];
		}

		return std::move(temp_str);
	}

	std::string idd_code() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 11) {
			temp_str = data_[10];
		}

		return std::move(temp_str);
	}

	std::string country_code() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 12) {
			temp_str = data_[11];
		}

		return std::move(temp_str);
	}

	std::string continent_code() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 13) {
			temp_str = data_[12];
		}

		return std::move(temp_str);
	}

	std::string idc() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 14) {
			temp_str = data_[13];
		}

		return std::move(temp_str);
	}

	std::string base_station() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 15) {
			temp_str = data_[14];
		}

		return std::move(temp_str);
	}

	std::string country_code3() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 16) {
			temp_str = data_[15];
		}

		return std::move(temp_str);
	}

	std::string european_union() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 17) {
			temp_str = data_[16];
		}

		return std::move(temp_str);
	}

	std::string currency_code() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 18) {
			temp_str = data_[17];
		}

		return std::move(temp_str);
	}

	std::string currency_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 19) {
			temp_str = data_[18];
		}

		return std::move(temp_str);
	}

	std::string anycast() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 20) {
			temp_str = data_[19];
		}

		return std::move(temp_str);
	}
private:
	std::vector<std::string> data_;
};

class city : public reader
{
public:
	explicit city(const std::string& file) : reader(file) {

	}

	virtual~city() = default;
	city_info find_info(const std::string& addr, const std::string& language) {
		return std::move(city_info(find(addr, language)));
	}
};

class base_station_info
{
public:
	explicit base_station_info(const std::vector<std::string>& data) {
		data_ = data;
	}

	std::string str() {
		std::stringstream sb;
		sb << "country_name:";
		sb << country_name();
		sb << "\n";
		sb << "region_name:";
		sb << region_name();
		sb << "\n";
		sb << "city_name:";
		sb << city_name();
		sb << "\n";
		sb << "owner_domain:";
		sb << owner_domain();
		sb << "\n";
		sb << "isp_domain:";
		sb << is_pDomain();
		sb << "\n";
		sb << "base_station:";
		sb << base_station();

		return std::move(sb.str());
	}

private:
	std::string country_name() {
		std::string temp_str;
		if (!data_.empty()) {
			temp_str = data_[0];
		}

		return std::move(temp_str);
	}

	std::string region_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 2) {
			temp_str = data_[1];
		}

		return std::move(temp_str);
	}

	std::string city_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 3) {
			temp_str = data_[2];
		}

		return std::move(temp_str);
	}

	std::string owner_domain() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 4) {
			temp_str = data_[3];
		}

		return std::move(temp_str);
	}

	std::string is_pDomain() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 5) {
			temp_str = data_[4];
		}

		return std::move(temp_str);
	}

	std::string base_station() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 6) {
			temp_str = data_[5];
		}

		return std::move(temp_str);
	}

private:
	std::vector<std::string> data_;
};

class base_station : public reader
{
public:
	explicit base_station(const std::string& file) :reader(file) {
	}

	virtual ~base_station() = default;
	base_station_info find_info(const std::string& addr, const std::string& language) {
		return std::move(base_station_info(find(addr, language)));
	}
};

class district_Info
{
public:
	explicit district_Info(const std::vector<std::string>& data) {
		data_ = data;
	}

	std::string str() {
		std::stringstream sb;
		sb << "country_name:";
		sb << country_name();
		sb << "\n";
		sb << "region_name:";
		sb << region_name();
		sb << "\n";
		sb << "city_name:";
		sb << city_name();
		sb << "\n";
		sb << "district_name:";
		sb << district_name();
		sb << "\n";
		sb << "china_admin_code:";
		sb << china_admin_code();
		sb << "\n";
		sb << "covering_radius:";
		sb << covering_radius();
		sb << "\n";
		sb << "latitude:";
		sb << latitude();
		sb << "\n";
		sb << "longitude:";
		sb << longitude();

		return std::move(sb.str());
	}
private:
	std::string country_name() {
		std::string temp_str;
		if (!data_.empty()) {
			temp_str = data_[0];
		}

		return std::move(temp_str);
	}

	std::string region_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 2) {
			temp_str = data_[1];
		}

		return std::move(temp_str);
	}

	std::string city_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 3) {
			temp_str = data_[2];
		}

		return std::move(temp_str);
	}

	std::string district_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 4) {
			temp_str = data_[3];
		}

		return std::move(temp_str);
	}

	std::string china_admin_code() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 5) {
			temp_str = data_[4];
		}

		return std::move(temp_str);
	}

	std::string covering_radius() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 6) {
			temp_str = data_[5];
		}

		return std::move(temp_str);
	}

	std::string latitude() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 7) {
			temp_str = data_[6];
		}

		return std::move(temp_str);
	}

	std::string longitude() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 8) {
			temp_str = data_[7];
		}

		return std::move(temp_str);
	}

private:
	std::vector<std::string> data_;
};

class district : public reader
{
public:
	explicit district(const std::string& file) :reader(file) {
	}

	virtual ~district() = default;
	district_Info find_info(const std::string& addr, const std::string& language) {
		return std::move(district_Info(find(addr, language)));
	}
};

class idc_info
{
public:
	explicit idc_info(const std::vector<std::string>& data) {
		data_ = data;
	}

	std::string str() {
		std::stringstream sb;
		sb << "country_name:";
		sb << country_name();
		sb << "\n";
		sb << "region_name:";
		sb << region_name();
		sb << "\n";
		sb << "city_name:";
		sb << city_name();
		sb << "\n";
		sb << "owner_domain:";
		sb << owner_domain();
		sb << "\n";
		sb << "isp_domain:";
		sb << isp_domain();
		sb << "\n";
		sb << "idc:";
		sb << idc();

		return std::move(sb.str());
	}
private:
	std::string country_name() {
		std::string temp_str;
		if (!data_.empty()) {
			temp_str = data_[0];
		}

		return std::move(temp_str);
	}

	std::string region_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 2) {
			temp_str = data_[1];
		}

		return std::move(temp_str);
	}

	std::string city_name() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 3) {
			temp_str = data_[2];
		}

		return std::move(temp_str);
	}

	std::string owner_domain() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 4) {
			temp_str = data_[3];
		}

		return std::move(temp_str);
	}

	std::string isp_domain() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 5) {
			temp_str = data_[4];
		}

		return std::move(temp_str);
	}

	std::string idc() {
		std::string temp_str;
		if (!data_.empty() && data_.size() >= 5) {
			temp_str = data_[4];
		}

		return std::move(temp_str);
	}
private:
	std::vector<std::string> data_;
};

class Idc : public reader
{
public:
	explicit Idc(const std::string& file) :reader(file) {

	}

	virtual ~Idc() = default;

	idc_info find_info(const std::string& addr, const std::string& language) {
		return std::move(idc_info(find(addr, language)));
	}
};

#endif // ipdb_h__
