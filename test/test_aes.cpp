#include <iostream>

#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <sstream>

#include <Algorithms.hpp>
#include <AES.hpp>

using namespace std;

class EncryptTest : public ::testing::Test {
public:
    std::chrono::system_clock::time_point start, end;
    uint8_t test_aes_key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t test_aes_iv[16]  = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
                                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}; 
    uint8_t out[1024];
    AES *aes;
    unsigned int outSizeinBytes=0;
protected:
};

TEST_F(EncryptTest, test_message_success)
{
    const int LEN = 64;
    const int len = 60; // for testing with the length other than power of 2
    uint8_t msg_in[LEN] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 
                        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 
                        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 
                        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t ct[LEN];
    uint8_t msg_dec[LEN];

    // aes = new AES(test_aes_key, test_aes_iv);
    aes = new AES(NULL, NULL);

    aes->encrypt(ct, msg_in, len);
    aes->decrypt(msg_dec, ct, len);

    cout << "message: " << endl;   
    BIO_dump_fp(stdout,(char*)msg_in,len);
    cout << "ciphertext: " << endl;
    BIO_dump_fp(stdout,(char*)ct,LEN);
    cout << "message(decrypted): " << endl;
    BIO_dump_fp(stdout,(char*)msg_dec,len);

    for (int i=0; i<len; i++) {
        ASSERT_EQ(msg_dec[i], msg_in[i]);
    }
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}