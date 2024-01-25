#pragma once

#include <cstdint>
#include <string.h>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/evp.h>
//#include "aes_locl.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// #include <bitset> // TODO remove include

extern unsigned int OPENSSL_ia32cap_P[];
#define AESNI_CAPABLE (OPENSSL_ia32cap_P[1]&(1<<(57-32)))
#define DEFAULT_CACHE_SIZE 10000

using namespace std;

class PRG
{

public:
    //
    // DEFAULT Ctor uses the default IV and cache size. Cache size default is set to 88  j
    // as this is a devisor of both 44 (used for 44 bytes) and 8 for AES pipeliningj
    // this means we compute 88*128 bits and cache them 
    PRG() { PRG(nullptr,(uint8_t*)m_defaultiv, DEFAULT_CACHE_SIZE); }
    //
    // CTOR for PRG with an input key, other parameters are default.
    PRG(uint8_t *key) { PRG(key,(uint8_t*)m_defaultiv, DEFAULT_CACHE_SIZE); }
    PRG(uint8_t *key, uint8_t *iv, int cacheSize=DEFAULT_CACHE_SIZE)
    {
        // 
        //key is always null, as we want to seed it from a random source
        if (key == nullptr)
        {
            //we seed from dev/random  in blocking mode to get 16 bytes 
            key = new uint8_t[16]();
            int randomData = open("/dev/random", O_RDONLY);
            char *myRandomData = (char *)key;
            size_t randomDataLen = 0; 
            while (randomDataLen < 16)
            {
                ssize_t result = read(randomData, myRandomData + randomDataLen, 16 - randomDataLen);
                if (result < 0)
                {
                    // error, unable to read /dev/random 
                }
                randomDataLen += result;
            }
            close(randomData);    
        }

        //Initialization of buffer counters and dome additional data structures
        m_key = key;
        m_iv = iv;
        m_idx = 0;
        m_cacheSize = cacheSize;
        m_cachedRandomsIdx = m_cacheSize;
  
        //INIT openssl. also creates the key schedule data structures internally
        m_penc = EVP_CIPHER_CTX_new();
        EVP_EncryptInit(m_penc, EVP_aes_128_ecb(),m_key, m_iv);
  
        m_cachedRandoms = new uint8_t[m_cacheSize*16]();
        m_ctr = new uint8_t[m_cacheSize*16]();

        //    cout << "[PRG] CACHE SIZE = " << m_cacheSize << endl;

        //This method created the first buffer of  CACHHE_SIZE*128Bit 
        prepare();
    };

    ~PRG() 
    {
        EVP_CIPHER_CTX_free(m_penc);
    };

    uint32_t getRandom()
    {
    	switch (m_idx)
    	{
        case 0:
            {
            	m_pIdx = (uint32_t*) getRandomBytes();
            	m_u1 = *m_pIdx;
            	m_pIdx++;
            	m_idx++;
            	return m_u1;
            }
            case 1:
            {
            	m_u2 = *m_pIdx;
            	m_pIdx++;
            	m_idx++;
            	return m_u2;
            }

            case 2:
            {
            	m_u3 = *m_pIdx;
            	m_pIdx++;
            	m_idx++;
            	return m_u3;
            }

            case 3:
            {
            	m_u4 = *m_pIdx;
            	m_idx = 0;
            	return m_u4;
            }
        }
        return 0;
    }

private:
    void checkAESNI();

    uint8_t m_defaultiv[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                       0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    uint8_t m_defaultkey[16];

    EVP_CIPHER_CTX * m_penc;

    const uint8_t * m_key;

    const uint8_t *m_iv;

    uint8_t * m_ctr;

    unsigned long m_ctr_count = 0;

    int m_cacheSize;
    int m_cachedRandomsIdx;
    uint8_t * m_cachedRandoms;

    int m_idx;
    uint32_t *m_pIdx;
    uint32_t m_u1;
    uint32_t m_u2;
    uint32_t m_u3;
    uint32_t m_u4;

    uint8_t *getRandomBytes()
    {
        if(m_cachedRandomsIdx==m_cacheSize)
        {
             prepare();
        }
        uint8_t *ret = m_cachedRandoms + m_cachedRandomsIdx*16;
        m_cachedRandomsIdx++;

        return ret;

    };

    //
    // CREATES A NEW BUFFER OF CACHE SIZE * 128 bit
    // 
    void prepare()
    {   
        int actual;	

    	unsigned long *p = (unsigned long *)m_ctr;
        // update and write the counter. we use a long counter so in every 128bit counter buffer, 
        // 64 low bits will be 0 and 64 high bits will include the counter

        for (int i = 0; i < m_cacheSize; i++)
        {
           p++;
           m_ctr_count = m_ctr_count+1;
           (*p) = m_ctr_count;
    	   p++;  
        }  
   
        //perform the encrytpion
        EVP_EncryptUpdate(m_penc, m_cachedRandoms, &actual , m_ctr, 16*m_cacheSize );

        //reset pointers
        m_cachedRandomsIdx = 0;
        m_idx = 0;
    };

 
};

class UnsupportAESNIException : public exception
{

public:
    virtual const char* what() const throw();
};

const char* UnsupportAESNIException::what() const throw()
{
    return "AESNI not supported at this computer\n program terminated";
}