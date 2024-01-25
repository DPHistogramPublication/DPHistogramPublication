#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <HashAbstract.hpp>

// test vector
static const uint8_t default_gmac_key[] = { 0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
               0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb };
static const uint8_t default_gmac_iv[] = { 0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7, 0xba, 0x01,
              0x36, 0xa7, 0x97, 0xf3 };
static const uint8_t gmac_aad[] = { 0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
               0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab };
static const uint8_t gmac_tag[] = { 0x20, 0x9f, 0xcc, 0x8d, 0x36, 0x75, 0xed, 0x93,
               0x8e, 0x9c, 0x71, 0x66, 0x70, 0x9d, 0xd9, 0x46 };
    
/**
 * Class that wraps GCM-128 procedure to hash arrays.
 */

/**
 * CTOR. Create an object to hash arrays using GCM-128 procedure.
 * @param key 128-bit key
 * @param iv initialization vector
 * @param ivSizeBytes size in bytes of the initialization vector
 */

class HashEncrypt : public HashAbstract
{
public:
    // key - 128-bit, iv changed size.
    HashEncrypt(const uint8_t *key, const uint8_t *iv=NULL,
                size_t ivSizeBytes=sizeof(default_gmac_iv))
    {
        // copy the 128-bit key
        if (key==NULL) key=default_gmac_key;
        memcpy(_key, key, 16);

        //copy the iv:
        _iv = new uint8_t[ivSizeBytes];
        if (iv==NULL) iv=default_gmac_iv;
        memcpy(_iv, iv, ivSizeBytes);

        if (!(_pctx = EVP_CIPHER_CTX_new())) {
            cout << "HashEncrypt::EVP_CIPHER_CTX_new: failed" << endl;
            exit(1);
        };

        if(!EVP_EncryptInit_ex(_pctx, EVP_aes_128_gcm(), NULL, NULL, NULL)){
            cout << "HashEncrypt::EVP_EncryptInit_ex: failed" << endl;
            exit(1);
        };

        if (!EVP_CIPHER_CTX_ctrl(_pctx, EVP_CTRL_GCM_SET_IVLEN, ivSizeBytes, NULL)){
            cout << "HashEncrypt::EVP_CIPHER_CTX_ctrl: failed" << endl;
            exit(1);
        };

    };


    ~HashEncrypt()
    {
	    EVP_CIPHER_CTX_free(_pctx);

        delete[] _iv;
        _iv = NULL;
    };

    void hashUpdate(uint8_t *in, int inSizeBytes) override
    {
        if (!EVP_EncryptInit_ex(_pctx, NULL, NULL, _key, _iv)){
            cout << "HashEncrypt::EVP_EncryptInit_ex: set key and IV failed" << endl;
            exit(1);
        };

        if(!EVP_EncryptUpdate(_pctx, NULL, &_unusedOutl, in, inSizeBytes)){
            cout << "HashEncrypt::EVP_EncryptUpdate: setting AAD failed" << endl;
            return;
        };
    };

    void hashFinal(uint8_t *out, uint32_t *outSizeBytes) override
    {
        if(!EVP_EncryptFinal_ex(_pctx, out, &_unusedOutl)){
            cout << "HashEncrypt::EVP_EncryptFinal_ex: failed" << endl;
            return;
        };

        if(!EVP_CIPHER_CTX_ctrl(_pctx, EVP_CTRL_AEAD_GET_TAG, _finalSizeBytes, out)){
            cout << "HashEncrypt::EVP_CIPHER_CTX_ctrl: failed" << endl;
            return;
        };
        *outSizeBytes = _finalSizeBytes;
    };

    // for debug
    int verifyHash(uint8_t *out) {
        if (memcmp(out,gmac_tag,sizeof(gmac_tag)) != 0 ) {
            cout << "=============================" << endl;
            cout << "HashEncrypt::verifyHash: failed" << endl;
            cout << "Expected:" << endl;
            BIO_dump_fp(stdout, (char*)gmac_tag, sizeof(gmac_tag)); 
            cout << "=============================" << endl;
            return 1;
        }
        else return 0;
    }    
    
    // void getDigest(uint8_t *out, uint32_t *outSizeBytes, 
    //                uint8_t *in, int inSizeBytes)
    // {
    //     //CXXPROF_ACTIVITY("hash");

    //     hashUpdate(in, inSizeBytes);
    //     hashFinal(out, outSizeBytes);
    // }



private:
    int _finalSizeBytes = 16;
    EVP_CIPHER_CTX *_pctx;
    uint8_t _key[16]; // 128-bit key
    uint8_t *_iv;     // initialization vector
    int _unusedOutl; 
};
