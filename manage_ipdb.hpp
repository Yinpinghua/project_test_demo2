#ifndef manage_ipdb_h__
#define manage_ipdb_h__

#include "ipdb.hpp"

class manage_ipdb {
public:
	static manage_ipdb& instance() {
		static manage_ipdb instance;
		return instance;
	}

	~manage_ipdb() = default;

	bool init_ipdb(const std::string& path) {
		if (!boost::filesystem::exists(path)) {
			std::cout << "ipdb path is not exist";
			return false;
		}

		try {
			ipdb_ = std::make_unique<city>(path);
			std::cout << "ipdb init ok.\r\n";
		}
		catch (...) {
			std::cout << "new mem fail" << std::endl;;
			return false;
		}

		return true;
	}

	bool get_ipdb_info(std::string& country_str, std::string& region_str, std::string& city_str, std::string& isp_str,
		const std::string& ip_str, const std::string& lang_str = "CN") {
		if (ipdb_ == nullptr) {
			return false;
		}

		auto maps = ipdb_->find_map(ip_str, lang_str);
		if (maps.size() == 0) {
			return false;
		}

		std::string field_str = "country_name";
		auto iter_find = maps.find(field_str);
		if (iter_find != maps.end()) {
			country_str = iter_find->second;
			if (is_valid_utf8(iter_find->second.c_str())) {
				country_str = boost::locale::conv::between(iter_find->second, "GBK", "UTF-8");
			}
		}

		field_str = "region_name";
		iter_find = maps.find(field_str);
		if (iter_find != maps.end()) {
			region_str = iter_find->second;
			if (is_valid_utf8(iter_find->second.c_str())) {
				region_str = boost::locale::conv::between(iter_find->second, "GBK", "UTF-8");
			}
		}

		field_str = "city_name";
		iter_find = maps.find(field_str);
		if (iter_find != maps.end()) {
			city_str = iter_find->second;
			if (is_valid_utf8(iter_find->second.c_str())) {
				city_str = boost::locale::conv::between(iter_find->second, "GBK", "UTF-8");
			}
		}

		field_str = "isp_domain";
		iter_find = maps.find(field_str);
		if (iter_find != maps.end()) {
			isp_str = iter_find->second;
			if (is_valid_utf8(iter_find->second.c_str())) {
				isp_str = boost::locale::conv::between(iter_find->second, "GBK", "UTF-8");
			}
		}

		std::cout << "query: " << ip_str << " ->\t [" << country_str << "][" << region_str << "][" << city_str << "][" << isp_str << "]\r\n";
		return true;
	}
private:
	manage_ipdb(const manage_ipdb&) = delete;
	manage_ipdb& operator==(const manage_ipdb&) = delete;
	manage_ipdb(const manage_ipdb&&) = delete;
	manage_ipdb& operator==(const manage_ipdb&&) = delete;
private:
	manage_ipdb() = default;
	std::unique_ptr<city> ipdb_;
};
#endif // manage_ipdb_h__
