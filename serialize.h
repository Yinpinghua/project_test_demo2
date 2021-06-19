#ifndef _SERIALIZE_HEADER_H_
#define _SERIALIZE_HEADER_H_
#include <sstream>   //std::stringstream
#include <vector>    //std::vector
#include <list>        //std::list
#include <set>       //std::set
#include <map>     //std::map
#include <utility>    // std::pair
#include <iterator>  //std::back_inserter
#include <string>  //memcpy
#include <forward_list>
#include <unordered_map>
#include <unordered_set>
#include <deque>

////////////////////////////////////////////
//Serialize for custom class object
//If your class object want to be serialized,
//Please derive for this base class
///////////////////////////////////////////

class Serializable
{
public:
	virtual std::string serialize() = 0;
	virtual unsigned int deserialize(const std::string&) = 0;
};

////////////////////////////////////////////////////
// define normal template function
////////////////////////////////////////////////////

//虚函数调用
template<typename SerializableType = Serializable>
static std::string serialize(SerializableType& a)
{
	return a.serialize();
}

template<typename SerializableType = Serializable>
static unsigned int deserialize(std::string& str, SerializableType& a)
{
	return a.deserialize(str);
}

/////////////////////////////////////////////////
//define special template function
//Serialize for C/C++ basic type
//examples: short,int,float,long long,double
/////////////////////////////////////////////////
#define DEF_BASIC_TYPE_SERIALIZE(Type) \
 template<> \
static std::string serialize(Type& b) \
{ \
        std::string ret; \
        ret.append((const char*)&b,sizeof(Type)); \
        return std::move(ret); \
}

#define DEF_BASIC_TYPE_DESERIALIZE(Type)  \
 template<> \
static unsigned int deserialize(std::string& str,Type& b)\
{ \
        memcpy(&b,str.data(),sizeof(Type)); \
        return sizeof(Type); \
}

#define DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(Type) \
        DEF_BASIC_TYPE_SERIALIZE(Type) \
        DEF_BASIC_TYPE_DESERIALIZE(Type)

DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(char)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(unsigned char)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(short int)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(unsigned short int)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(unsigned int)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(int)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(long int)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(unsigned long int)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(float)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(long long int)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(unsigned long long int)
DEF_BASIC_TYPE_SERIALIZE_AND_DESERIALIZE(double)

//////////////////////////////////////
//Serialize for type string
/////////////////////////////////////

// for c++ type std::string
template<>
static std::string serialize(std::string& s)
{
	unsigned int len = static_cast<unsigned int>(s.size());
	std::string ret;
	ret.append(::serialize(len));
	ret.append(s.data(), len);
	return std::move(ret);
}

template<>
static unsigned int deserialize(std::string& str, std::string& s)
{
	unsigned int len;
	::deserialize(str, len);
	s = str.substr(sizeof(len), len);
	return sizeof(int) + len;
}

////////////////////////////////////////////
//define input and output stream
//for serialize data struct
////////////////////////////////////////////

class out_stream
{
public:
	out_stream() : os_(std::ios::binary | std::ios::out)
	{

	}

	~out_stream() = default;

	template<typename SerializableType>
	out_stream& operator<< (SerializableType& a)
	{
		std::string x = ::serialize(a);
		os_.write(x.data(), x.size());
		return *this;
	}

	template<typename BasicType>
	out_stream& operator<< (std::vector<BasicType>& a)
	{
		unsigned int len = static_cast<unsigned int>(a.size());

		std::string x = ::serialize(len);
		os_.write(x.data(), x.size());

		for (unsigned int i = 0; i < len; ++i) {
			std::string item = ::serialize(a[i]);
			os_.write(item.data(), item.size());
		}

		return *this;
	}

	template<typename BasicType>
	out_stream& operator<< (std::list<BasicType>& a)
	{
		std::vector<BasicType> temp;
		std::copy(a.begin(), a.end(), std::back_inserter(temp));
		return this->operator<< (temp);
	}

	//c++11单链表
	template<typename BasicType>
	out_stream& operator<< (std::forward_list<BasicType>& a)
	{
		std::vector<BasicType> temp;
		std::copy(a.begin(), a.end(), std::back_inserter(temp));
		return this->operator<< (temp);
	}

	template<typename BasicType>
	out_stream& operator<< (std::deque<BasicType>& a)
	{
		std::vector<BasicType> temp;
		std::copy(a.begin(), a.end(), std::back_inserter(temp));
		return this->operator<< (temp);
	}

	template<typename BasicType>
	out_stream& operator<< (std::set<BasicType>& a)
	{
		std::vector<BasicType> temp;
		std::copy(a.begin(), a.end(), std::back_inserter(temp));
		return this->operator<< (temp);
	}

	template<typename BasicType>
	out_stream& operator<< (std::unordered_set<BasicType>& a)
	{
		std::vector<BasicType> temp;
		std::copy(a.begin(), a.end(), std::back_inserter(temp));
		return this->operator<< (temp);
	}

	template<typename BasicType>
	out_stream& operator<< (std::unordered_multiset<BasicType>& a)
	{
		std::vector<BasicType> temp;
		std::copy(a.begin(), a.end(), std::back_inserter(temp));
		return this->operator<< (temp);
	}

	template<typename BasicTypeA, typename BasicTypeB>
	out_stream& operator<< (std::map<BasicTypeA, BasicTypeB>& a)
	{
		std::vector<BasicTypeA> temp_key;
		std::vector<BasicTypeB> temp_val;

		for (const auto& info : a) {
			temp_key.emplace_back(info.first);
			temp_val.emplace_back(info.second);
		}

		//typename std::map<BasicTypeA, BasicTypeB>::const_iterator it = a.begin();
		//for (;it != a.end();++it){
		//	tempKey.emplace_back(it->first);
		//	tempVal.emplace_back(it->second);
		//}

		this->operator<< (temp_key);
		return this->operator<< (temp_val);
	}

	template<typename BasicTypeA, typename BasicTypeB>
	out_stream& operator<< (std::unordered_map<BasicTypeA, BasicTypeB>& a)
	{
		std::vector<BasicTypeA> temp_key;
		std::vector<BasicTypeB> temp_val;

		for (const auto& info : a) {
			temp_key.emplace_back(info.first);
			temp_val.emplace_back(info.second);
		}

		//typename std::unordered_map<BasicTypeA, BasicTypeB>::const_iterator it = a.begin();
		////auto it = a.begin();
		//for (;it != a.end();++it){
		//	tempKey.emplace_back(it->first);
		//	tempVal.emplace_back(it->second);
		//}

		this->operator<< (temp_key);
		return this->operator<< (temp_val);
	}

	template<typename BasicTypeA, typename BasicTypeB>
	out_stream& operator<< (std::unordered_multimap<BasicTypeA, BasicTypeB>& a)
	{
		std::vector<BasicTypeA> temp_key;
		std::vector<BasicTypeB> temp_val;

		for (const auto& info : a) {
			temp_key.emplace_back(info.first);
			temp_val.emplace_back(info.second);
		}

		//typename std::unordered_map<BasicTypeA, BasicTypeB>::const_iterator it = a.begin();
		////auto it = a.begin();
		//for (;it != a.end();++it){
		//	tempKey.emplace_back(it->first);
		//	tempVal.emplace_back(it->second);
		//}

		this->operator<< (temp_key);
		return this->operator<< (temp_val);
	}

	std::string str()
	{
		return std::move(os_.str());
	}

public:
	std::ostringstream os_;
};

class in_stream
{
public:
	in_stream(const std::string& s) : str_(s,std::ios::binary | std::ios::in), total_(s.size())
	{
	}

	~in_stream() = default;

	template<typename SerializableType>
	in_stream& operator>> (SerializableType& a)
	{
		int ret = ::deserialize(str_, a);
		str_ = str_.substr(ret);
		return *this;
	}

	template<typename BasicType>
	in_stream& operator>> (std::vector<BasicType>& a)
	{
		unsigned int len = 0;
		int ret = ::deserialize(str_, len);
		str_ = str_.substr(ret);

		for (unsigned int i = 0; i < len; ++i) {
			BasicType item;
			int size = ::deserialize(str_, item);
			str_ = str_.substr(size);
			a.emplace_back(item);
		}

		return *this;
	}

	template<typename BasicType>
	in_stream& operator>> (std::list<BasicType>& a)
	{
		std::vector<BasicType> temp;
		in_stream& ret = this->operator>> (temp);
		if (temp.size() > 0) {
			std::copy(temp.begin(), temp.end(), std::back_inserter(a));
		}

		return ret;
	}

	//c++11单链表
	template<typename BasicType>
	in_stream& operator>> (std::forward_list<BasicType>& a)
	{
		std::vector<BasicType> temp;
		in_stream& ret = this->operator>> (temp);
		if (temp.size() > 0) {
			std::copy(temp.begin(), temp.end(), std::back_inserter(a));
		}
	}

	template<typename BasicType>
	in_stream& operator>> (std::deque<BasicType>& a)
	{
		std::vector<BasicType> temp;
		in_stream& ret = this->operator>> (temp);
		if (temp.size() > 0) {
			std::copy(temp.begin(), temp.end(), std::back_inserter(a));
		}

		return ret;
	}

	template<typename BasicType>
	in_stream& operator>> (std::set<BasicType>& a)
	{
		std::vector<BasicType> temp;
		in_stream& ret = this->operator>> (temp);
		for (const auto& info : temp) {
			a.emplace(info);
		}

		return ret;
	}

	template<typename BasicType>
	in_stream& operator>> (std::multiset<BasicType>& a)
	{
		std::vector<BasicType> temp;
		in_stream& ret = this->operator>> (temp);
		for (const auto& info : temp) {
			a.emplace(info);
		}

		return ret;
	}

	template<typename BasicType>
	in_stream& operator>> (std::unordered_set<BasicType>& a)
	{
		std::vector<BasicType> temp;
		in_stream& ret = this->operator>> (temp);
		for (const auto& info : temp) {
			a.emplace(info);
		}

		return ret;
	}

	template<typename BasicType>
	in_stream& operator>> (std::unordered_multiset<BasicType>& a)
	{
		std::vector<BasicType> temp;
		in_stream& ret = this->operator>> (temp);
		for (const auto& info : temp) {
			a.emplace(info);
		}

		return ret;
	}

	template<typename BasicTypeA, typename BasicTypeB>
	in_stream& operator>> (std::map<BasicTypeA, BasicTypeB>& a)
	{
		std::vector<BasicTypeA> temp_key;
		std::vector<BasicTypeB> temp_val;

		this->operator>> (temp_key);
		in_stream& ret = this->operator>> (temp_val);

		if (temp_key.size() > 0 && temp_val.size() == temp_key.size()) {
			size_t key_size = temp_key.size();
			for (size_t i = 0; i < key_size; ++i) {
				//a.insert(std::make_pair<BasicTypeA, BasicTypeB>(tempKey[i], tempVal[i]));效率低
				a.emplace(temp_key[i], temp_val[i]);
			}
		}

		return ret;
	}

	template<typename BasicTypeA, typename BasicTypeB>
	in_stream& operator>> (std::multimap<BasicTypeA, BasicTypeB>& a)
	{
		std::vector<BasicTypeA> temp_key;
		std::vector<BasicTypeB> temp_val;

		this->operator>> (temp_key);
		in_stream& ret = this->operator>> (temp_val);

		if (temp_key.size() > 0 && temp_val.size() == temp_key.size()) {
			size_t key_size = temp_key.size();
			for (size_t i = 0; i < key_size; ++i) {
				//a.insert(std::make_pair<BasicTypeA, BasicTypeB>(tempKey[i], tempVal[i]));效率低
				a.emplace(temp_key[i], temp_val[i]);
			}
		}

		return ret;
	}

	template<typename BasicTypeA, typename BasicTypeB>
	in_stream& operator>> (std::unordered_map<BasicTypeA, BasicTypeB>& a)
	{
		std::vector<BasicTypeA> temp_key;
		std::vector<BasicTypeB> temp_val;

		this->operator>> (temp_key);
		in_stream& ret = this->operator>> (temp_val);

		if (temp_key.size() > 0 && temp_val.size() == temp_key.size()) {
			size_t key_size = temp_key.size();
			for (size_t i = 0; i < key_size; ++i) {
				//a.insert(std::make_pair<BasicTypeA, BasicTypeB>(tempKey[i], tempVal[i]));//会报错
				a.emplace(temp_key[i], temp_val[i]);
			}
		}

		return ret;
	}

	template<typename BasicTypeA, typename BasicTypeB>
	in_stream& operator>> (std::unordered_multimap<BasicTypeA, BasicTypeB>& a)
	{
		std::vector<BasicTypeA> temp_key;
		std::vector<BasicTypeB> temp_val;

		this->operator>> (temp_key);
		in_stream& ret = this->operator>> (temp_val);

		if (temp_key.size() > 0 && temp_val.size() == temp_key.size()) {
			size_t key_size = temp_key.size();
			for (size_t i = 0; i < key_size; ++i) {
				//a.insert(std::make_pair<BasicTypeA, BasicTypeB>(tempKey[i], tempVal[i]));//会报错
				a.emplace(temp_key[i], temp_val[i]);
			}
		}

		return ret;
	}

	unsigned int size()
	{
		return static_cast<unsigned int>(total_ - str_.size());
	}
protected:
	std::string str_;
	size_t total_;
};

///////////////////////////////////////////
//!!!!!!!!!!!!!
//!!   NOTE  !!
//!!!!!!!!!!!!!
//Now,we can't serialize pointer type,likes
//char* var,char var[],int *var,int var[]
//etc,if you need to serialize array data,
//we suggest you use std::vector instead.
///////////////////////////////////////////

#endif
