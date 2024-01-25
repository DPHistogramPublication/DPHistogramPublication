#pragma once

#include <string>
#include <iostream>
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

static inline void sha256(unsigned char *hash, std::string str) {
    // unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, str.c_str(), str.size());
    SHA256_Final(hash, &sha_ctx);
    // stringstream ss;
    // for (int i=0; i<SHA256_DIGEST_LENGTH; i++) {
    //     ss << hex << setw(2) << setfill('0') << (int)hash[i];
    // }
    // return ss.str();
}

static inline void hmac_sha256(unsigned char *digest, const uint8_t *key, size_t klen, const uint8_t *data, size_t dlen) {
    // uint8_t digest[EVP_MAX_MD_SIZE];
    uint32_t dilen{};

    auto p = ::HMAC(
        ::EVP_sha256()
        , key
        , klen
        , (uint8_t*)data
        , dlen
        , digest
        , &dilen
    );
    assert(p);
}
