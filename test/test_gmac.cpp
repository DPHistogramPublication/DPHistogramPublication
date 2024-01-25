#include <iostream>

#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <sstream>

#include <Algorithms.hpp>
#include <HashEncrypt.hpp>
#include <PRG.hpp>

using namespace std;

class HashTest : public ::testing::Test {
public:
    std::chrono::system_clock::time_point start, end;
    uint8_t test_key[16] = { 0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
                                0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb };
    uint8_t test_aad[16] = { 0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
                                0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab };
    HashEncrypt *test_hash;
    uint8_t out[1024], out2[1024];
    uint32_t outSizeinBytes=0, outSizeinBytes2=0;
protected:
};

TEST_F(HashTest, test_message_success)
{
    test_hash = new HashEncrypt(test_key); // use default iv
    uint32_t inSizeBytes = sizeof(test_aad);
    
    test_hash->getDigest(out, &outSizeinBytes, 
                            test_aad, inSizeBytes);
    
    cout << "in size : " << inSizeBytes << endl; 
    cout << "out size: " << outSizeinBytes << endl;
    cout << "messagge: " << endl;
    BIO_dump_fp(stdout,(char*)test_aad,16);
    cout << "hash value: " << endl;
    BIO_dump_fp(stdout,(char*)out,16);
    
    ASSERT_EQ(test_hash->verifyHash(out),0);
}

TEST_F(HashTest, test_message_failed)
{
    test_hash = new HashEncrypt(test_key,NULL);
    std::string test_msg="\'This is a wrong message for testing.\'";
    uint32_t inSizeBytes = test_msg.length();
    
    test_hash->getDigest(out, &outSizeinBytes,
                            (uint8_t*)test_msg.c_str(), inSizeBytes);
    
    ASSERT_EQ(test_hash->verifyHash(out),1);

    cout << "in size : " << inSizeBytes << endl; 
    cout << "out size: " << outSizeinBytes << endl;
    cout << "message: " << test_msg.c_str() << endl;
    cout << "hash value: " << endl;
    BIO_dump_fp(stdout,(char*)out,16);
}

TEST_F(HashTest, test_compare)
{
    test_hash = new HashEncrypt(test_key,NULL);
    std::string test_msg1 = "hogehoge";
    std::string test_msg2 = "hogehoge";
    uint32_t inSizeBytes1 = test_msg1.length();
    uint32_t inSizeBytes2 = test_msg2.length();
    
    test_hash->getDigest(out, &outSizeinBytes,
                            (uint8_t*)test_msg1.c_str(), inSizeBytes1);
    test_hash->getDigest(out2, &outSizeinBytes2,
                        (uint8_t*)test_msg2.c_str(), inSizeBytes2);
    
    ASSERT_NE(outSizeinBytes, 0);
    ASSERT_EQ(outSizeinBytes, outSizeinBytes2);
    for (size_t i=0; i<outSizeinBytes; i++) {
        ASSERT_EQ(out[i], out2[i]);
    }
    cout << "message size: " << inSizeBytes1 << endl;
    cout << "hash 1: " << endl;
    BIO_dump_fp(stdout,(char*)out,outSizeinBytes);
    cout << "hash 2: " << endl;
    BIO_dump_fp(stdout,(char*)out2,outSizeinBytes2);
}


int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}