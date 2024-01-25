#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>

static const uint8_t default_aes_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t default_aes_iv[16]  = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
                                            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}; 

/**
 * Class that wraps AES-CTR-128 procedure to hash arrays.
 */

/**
 * CTOR. Create an object to hash arrays using AES-CTR-128 procedure.
 * @param key 128-bit key
 * @param iv initialization vector
 * @param ivSizeBytes size in bytes of the initialization vector
 */

using namespace std;

class AES
{
public:
    // key - 128-bit, iv changed size.
    AES(const uint8_t *key=NULL, const uint8_t *iv=NULL,
                size_t ivSizeBytes=sizeof(default_aes_iv))
    {
        // copy the 128-bit key
        if (key==NULL) key=default_aes_key;
        memcpy(_key, key, 16);
    
        // cout << "_key: " << endl;   
        // BIO_dump_fp(stdout,(char*)_key,16);

        //copy the iv:
        _iv = new uint8_t[ivSizeBytes];
        if (iv==NULL) iv=default_aes_iv;
        memcpy(_iv, iv, ivSizeBytes);
        
        // cout << "_iv: " << endl;   
        // BIO_dump_fp(stdout,(char*)_iv,16);

        if (!(_pctx = EVP_CIPHER_CTX_new())) {
            cout << "AES::EVP_CIPHER_CTX_new: failed" << endl;
            exit(1);
        };


        // if (!EVP_CIPHER_CTX_ctrl(_pctx, _finalSizeBytes, ivSizeBytes, NULL)){
        //     cout << "AES::EVP_CIPHER_CTX_ctrl: failed" << endl;
        //     exit(1);
        // };

        // if (!EVP_EncryptInit_ex(_pctx, NULL, NULL, gmac_key, gmac_iv)){
        //     cout << "AES::EVP_EncryptInit_ex: set key and IV failed" << endl;
        //     exit(1);
        // };
    };

    ~AES()
    {
	    EVP_CIPHER_CTX_free(_pctx);
        delete[] _iv;
        _iv = NULL;
    };

    void encrypt(uint8_t *out, uint8_t *in, int size) {
        int out_len, in_len = size;

        if(!EVP_EncryptInit_ex(_pctx, EVP_aes_128_ctr(), NULL, _key, _iv)){
            cout << "AES::EVP_EncryptInit_ex: failed" << endl;
            return;
        };

        if(!EVP_EncryptUpdate(_pctx, out, &out_len, in, in_len)) {
            cout << "AES::encrypt: EVP_EncryptUpdate failed" << endl;
            return;
        }

        if (out_len != in_len) {
            cout << "AES::encrypt: encrypt out_le(n" << out_len << ") != in_len(" << in_len << ")" << endl;
        }
    };

    void decrypt(uint8_t *out, uint8_t *in, int size) {
        int out_len, in_len = size;
        
        if(!EVP_DecryptInit_ex(_pctx, EVP_aes_128_ctr(), NULL, _key, _iv)){
            cout << "AES::EVP_DecryptInit_ex: failed" << endl;
            return;
        };

        if (!EVP_DecryptUpdate(_pctx, out, &out_len, in, in_len)) {
            cout << "AES::decrypt: EVP_DecryptUpdate failed" << endl;
        }

        if (out_len != in_len) {
            cout << "AES::decrypt: encrypt out_le(n" << out_len << ") != in_len(" << in_len << ")" << endl;
        }
    };

private:
    int _finalSizeBytes = 16;
    EVP_CIPHER_CTX *_pctx;
    uint8_t _key[16]; // 128-bit key
    uint8_t *_iv;     // initialization vector
};
