#pragma once

#include <openssl/evp.h>
#include <iostream> //for testing

//#define USECXXPROF
//#include <cxxprof_static/CxxProf.h>


using namespace std;

/**
 * Abstract class for defining the interface of hasing: init, update and final
 */
class HashAbstract
{
public:
    virtual void hashUpdate(uint8_t *in, int inSizeBytes) = 0;
    // hashFinal implementation should set initialized to false
    virtual void hashFinal(uint8_t *out, uint32_t *outSizeBytes) = 0;

    void getDigest(uint8_t *out, uint32_t *outSizeBytes, 
                   uint8_t *in, int inSizeBytes)
    {
        //CXXPROF_ACTIVITY("hash");

        hashUpdate(in, inSizeBytes);
        hashFinal(out, outSizeBytes);
    }

};