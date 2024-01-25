#pragma once

#include <string>
#include <iostream>
#include <bitset>
#include <iomanip>
#include <cstring>
#include <sstream>
#include <map>
#include <boost/bimap/bimap.hpp>
#include <boost/bimap/multiset_of.hpp>
#include <boost/foreach.hpp>
#include <openssl/sha.h>
#include <openssl/hmac.h>

using namespace std;

template <class T>
void print(const T& c, std::ostream& os = std::cout) {
    std::copy(std::begin(c), std::end(c), std::ostream_iterator<typename T::value_type>(os, ", "));
    os << std::endl;
}

template<typename T>
ostream& operator << (ostream& os, vector<T>& vec) {
    os << "{";
    for (size_t i=0; i<vec.size(); i++) {
        os << vec[i] << (i+1 == vec.size() ? "" : " ");
    }
    os << "}";
    return os;
}

static inline std::string hex2str(const unsigned char *buf, int size) {
    stringstream ss;
    for (int i=0; i<size; i++) {
        ss << hex << setw(2) << setfill('0') << (int)buf[i];
    }
    return ss.str();
}

static inline std::string bin2str(const unsigned char *buf, int size) {
    stringstream ss;
    for (int i=0; i<size; i++) {
        ss << bitset<8>(buf[i]).to_string();
    }
    return ss.str();
}



// xor shift
struct Xor128 {
	unsigned x, y, z, w;
	Xor128(int _w) { x = 123456789; y = 362436069; z = 521288629; w = _w; }
	unsigned nextUInt() {
		unsigned t = (x ^ (x << 11));
		x = y; y = z; z = w;
		return (w = (w ^ (w >> 19)) ^ (t ^ (t >> 8)));
	}
};
