#include <iostream>
#include <fstream>

#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <unordered_set>

#include <Algorithms.hpp>
#include <util.hpp>
#include <hmac.hpp>
// #include <fmt/format.h>

using namespace std;

class HMACTest : public ::testing::Test {
public:
    std::chrono::system_clock::time_point start, end;
    uint8_t test_key[32] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
                        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}; 
    uint8_t r1[32] = {0x5a, 0x3b, 0x7f, 0xcd, 0xc6, 0xc1, 0x9d, 0xf6, 
                    0xb7, 0xe7, 0x58, 0x79, 0x75, 0x6c, 0x54, 0xa9, 
                    0xfe, 0x82, 0x13, 0x06, 0x87, 0xf2, 0xa5, 0x92, 
                    0xb3, 0x7d, 0xe0, 0x63, 0x90, 0x16, 0x53, 0x99};
    uint8_t r2[32] = {0x47, 0x4a, 0xd1, 0xb1, 0x4f, 0xe8, 0x23, 0x01,
                    0xbf, 0x44, 0xef, 0x64, 0x42, 0xb0, 0xee, 0x4b, 
                    0xbd, 0xc9, 0xb7, 0xa4, 0x38, 0xbf, 0x5b, 0x18, 
                    0x32, 0xe7, 0x38, 0x97, 0x73, 0xeb, 0x12, 0x45};
    uint8_t r3[32] = {0xc7, 0xc1, 0x0f, 0x77, 0x6c, 0x67, 0xf6, 0x9f, 
                    0x1a, 0xd4, 0x7b, 0x24, 0x85, 0x37, 0x79, 0xcb, 
                    0x42, 0x28, 0x99, 0xb8, 0xa5, 0xbd, 0xff, 0xd0, 
                    0x36, 0x33, 0x5c, 0xd2, 0x43, 0x18, 0xc4, 0xa9};
    uint8_t t1[32] = {0x4c, 0xa0, 0x35, 0xe8, 0xbc, 0xec, 0xeb, 0x64, 
                    0xb2, 0xb7, 0x72, 0x46, 0x23, 0xf7, 0x47, 0x3c, 
                    0x16, 0xb4, 0xf2, 0xf1, 0x9f, 0xf8, 0x46, 0x55,
                    0x95, 0xee, 0x81, 0x5c, 0xf6, 0xbc, 0x0c, 0x24};
    uint8_t t2[32] = {0xd4, 0xa4, 0xbf, 0x4d, 0xd2, 0x7a, 0xce, 0xe1,
                    0x70, 0x69, 0x95, 0x60, 0xfc, 0x9b, 0x03, 0x56, 
                    0x76, 0x94, 0x92, 0x6f, 0x6e, 0x41, 0xeb, 0x2d, 
                    0x28, 0x18, 0x8f, 0x82, 0x74, 0xf4, 0x82, 0x1d};
    uint8_t t3[32] = {0x95, 0xb6, 0x5b, 0xdc, 0xd4, 0x87, 0xa2, 0x94, 
                    0x1b, 0xaf, 0xc1, 0x50, 0x22, 0x75, 0xff, 0x73, 
                    0xb6, 0x81, 0x90, 0x73, 0xbd, 0x8d, 0xed, 0x30, 
                    0xf9, 0x8c, 0x38, 0x4f, 0x10, 0x5c, 0xd5, 0x7e};
protected:
};

// TEST_F(HMACTest, test_sha256)
// {
//     unsigned char hash[SHA256_DIGEST_LENGTH];
//     string test[8];
//     test[0] = "1234567890_1";
//     test[1] = "1234567890_2";
//     test[2] = "1234567890_3";
//     test[3] = "1234567890_4";
//     test[4] = "1234567890_5";
//     test[5] = "1234567890_6";
//     test[6] = "1234567890_7";
//     test[7] = "1234567890_8";
    
//     cout << "SHA256_DIGEST_LENGTH: " << SHA256_DIGEST_LENGTH << endl;

//     for (int i=0; i<8; i++) {
//         sha256(hash, test[i]); 
//         stringstream ss;
//         cout << "hash " << i << ": " << hex2str(hash, SHA256_DIGEST_LENGTH) << endl;
//     }
// }

// TEST_F(HMACTest, test_hmac_sha256)
// {
//     unsigned char digest[SHA256_DIGEST_LENGTH];
//     size_t keylen = 32;
//     string test[8];
//     test[0] = "1234567890_0";
//     test[1] = "1234567890_1";
//     test[2] = "1234567890_2";
//     test[3] = "1234567890_3";
//     test[4] = "1234567890_4";
//     test[5] = "1234567890_5";
//     test[6] = "1234567890_6";
//     test[7] = "1234567890_7";
    
//     cout << "SHA256_DIGEST_LENGTH: " << SHA256_DIGEST_LENGTH << endl;

//     for (int i=0; i<8; i++) {
//         hmac_sha256(digest, test_key, keylen, reinterpret_cast<const uint8_t*>(test[i].c_str()), test[i].size()); 
//         stringstream ss;
//         cout << "digest " << i << ": " << hex2str(digest, SHA256_DIGEST_LENGTH) << endl;
//     }
// }

TEST_F(HMACTest, test_prf_io_pairs_r1)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t keylen = 32;

    ofstream ofs_csv_file("r1.csv");

    // ofs_csv_file << "key = " << hex2str(r1, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << "key = " << bin2str(r1, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << endl;

    for (int i=0; i<2048; i++) {
        string test = to_string(i);
        hmac_sha256(digest, r1, keylen, reinterpret_cast<const uint8_t*>(test.c_str()), test.size()); 
        stringstream ss;
        // ofs_csv_file << i << ", " << hex2str(digest, SHA256_DIGEST_LENGTH) << endl;
        ofs_csv_file << i << ", " << bin2str(digest, SHA256_DIGEST_LENGTH) << endl;
    }
}

TEST_F(HMACTest, test_prf_io_pairs_r2)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t keylen = 32;

    ofstream ofs_csv_file("r2.csv");

    // ofs_csv_file << "key = " << hex2str(r2, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << "key = " << bin2str(r2, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << endl;

    for (int i=0; i<2048; i++) {
        string test = to_string(i);
        hmac_sha256(digest, r2, keylen, reinterpret_cast<const uint8_t*>(test.c_str()), test.size()); 
        stringstream ss;
        // ofs_csv_file << i << ", " << hex2str(digest, SHA256_DIGEST_LENGTH) << endl;
        ofs_csv_file << i << ", " << bin2str(digest, SHA256_DIGEST_LENGTH) << endl;
    }
}

TEST_F(HMACTest, test_prf_io_pairs_r3)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t keylen = 32;

    ofstream ofs_csv_file("r3.csv");

    // ofs_csv_file << "key = " << hex2str(r3, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << "key = " << bin2str(r3, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << endl;

    for (int i=0; i<2048; i++) {
        string test = to_string(i);
        hmac_sha256(digest, r3, keylen, reinterpret_cast<const uint8_t*>(test.c_str()), test.size()); 
        stringstream ss;
        // ofs_csv_file << i << ", " << hex2str(digest, SHA256_DIGEST_LENGTH) << endl;
        ofs_csv_file << i << ", " << bin2str(digest, SHA256_DIGEST_LENGTH) << endl;
    }
}

TEST_F(HMACTest, test_prf_io_pairs_t1)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t keylen = 32;

    ofstream ofs_csv_file("t1.csv");

    // ofs_csv_file << "key = " << hex2str(t1, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << "key = " << bin2str(t1, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << endl;

    for (int i=0; i<2048; i++) {
        string test = to_string(i);
        hmac_sha256(digest, t1, keylen, reinterpret_cast<const uint8_t*>(test.c_str()), test.size()); 
        stringstream ss;
        // ofs_csv_file << i << ", " << hex2str(digest, SHA256_DIGEST_LENGTH) << endl;
        ofs_csv_file << i << ", " << bin2str(digest, SHA256_DIGEST_LENGTH) << endl;
    }
}

TEST_F(HMACTest, test_prf_io_pairs_t2)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t keylen = 32;

    ofstream ofs_csv_file("t2.csv");

    // ofs_csv_file << "key = " << hex2str(t2, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << "key = " << bin2str(t2, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << endl;

    for (int i=0; i<2048; i++) {
        string test = to_string(i);
        hmac_sha256(digest, t2, keylen, reinterpret_cast<const uint8_t*>(test.c_str()), test.size()); 
        stringstream ss;
        // ofs_csv_file << i << ", " << hex2str(digest, SHA256_DIGEST_LENGTH) << endl;
        ofs_csv_file << i << ", " << bin2str(digest, SHA256_DIGEST_LENGTH) << endl;
    }
}

TEST_F(HMACTest, test_prf_io_pairs_t3)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    size_t keylen = 32;

    ofstream ofs_csv_file("t3.csv");

    // ofs_csv_file << "key = " << hex2str(t3, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << "key = " << bin2str(t3, SHA256_DIGEST_LENGTH) << endl;
    ofs_csv_file << endl;

    for (int i=0; i<2048; i++) {
        string test = to_string(i);
        hmac_sha256(digest, t3, keylen, reinterpret_cast<const uint8_t*>(test.c_str()), test.size()); 
        stringstream ss;
        // ofs_csv_file << i << ", " << hex2str(digest, SHA256_DIGEST_LENGTH) << endl;
        ofs_csv_file << i << ", " << bin2str(digest, SHA256_DIGEST_LENGTH) << endl;
    }
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}