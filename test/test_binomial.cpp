#include <iostream>
#include <fstream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <vector>

#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <sstream>

#include <Algorithms.hpp>
#include <HashEncrypt.hpp>
#include <PRG.hpp>

#include <hmac.hpp>

using namespace std;

class BinomialTest : public ::testing::Test {
public:
    std::chrono::system_clock::time_point start, end;
    uint8_t key[16] = { 0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
                                0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb };
    uint8_t aad[16] = { 0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
                                0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab };
    HashEncrypt *test_hash;
    size_t keylen = 32;
    uint8_t out[1024], out2[1024];
    uint32_t outSizeinBytes=0, outSizeinBytes2=0;

    int m = 3, t = 1; // number of servers, threshold
    double eps = 4.0;
    // double dlt = pow(2, -10); // privacy budget
    double dlt = pow(10, -8); // privacy budget
    int lam = 128; // security

    int L = 102400; // length of an output of PRF
    double D = 1; // sensitivity
    double D1 = 2;
    double D2 = sqrt(2.0);
    double Dinf = 1;

    int NumAve = 100; // number of iterations

protected:
    void setBit(std::uint8_t& byte, int position, int value) {
        if (value == 1) {
            byte |= (1 << position);
        } else {
            byte &= ~(1 << position);
        }
    }
};

TEST_F(BinomialTest, test_FS_MAE)
{
    int d = 625; // number of binomial noises
    double c1 = 2 * D2 * sqrt(2 * log(1.25 / dlt));
    double c2 = 4 / (1 - dlt / 10) * (D2 * 7 * sqrt(2.0) / 4 * sqrt(log(10 / dlt)) + D1*1 / 3)
                  + 4 * (Dinf * (2/3) * log(1.25 / dlt) + Dinf * (2/3) * log(20*d / dlt) * log(10 / dlt));
    double M = floor(eps * (1 / (c1 / sqrt((double)L) + c2 / L)) );

    if (M == 0) {
        std::cout << "These privacy budgets cannot be achieved." << std::endl;
    } else {
        std::string filename = "csv/Binomial_FS_MAE.csv";
        std::ofstream outFile(filename.c_str(), std::ios::app);

        int Amax = static_cast<int>(tgamma(m + 1) / (tgamma(t + 1) * tgamma(m - t + 1)));
        std::vector<std::vector<std::vector<int>>> k(Amax, std::vector<std::vector<int>>(1, std::vector<int>(lam, 0)));
        std::vector<std::vector<double>> noise(NumAve, std::vector<double>(d, 0));
        std::vector<double> err(NumAve, 0); // err is the sum of the absolute values of d laplace noises
        double err_ave = 0;

        srand(time(0)); // seed the random number generator

        std::array<std::uint8_t, 16> hash_key[Amax];

        for (int i = 0; i < NumAve; ++i) {
            for (int A = 0; A < Amax; ++A) {
                for (int l = 0; l < lam; ++l) {
                    k[A][0][l] = rand() % 2; // lam random numbers between 0 and 1
                    hash_key[A][l / 8] |= (k[A][0][i] & 1) << (l % 8);
                }
            }

            for (int a = 0; a < d; ++a) { // a is an input to PRF
                std::vector<std::vector<std::vector<int>>> b(Amax, std::vector<std::vector<int>>(1, std::vector<int>(L, 0)));
                std::vector<double> ell(Amax, 0);

                unsigned char digest[SHA256_DIGEST_LENGTH];
                for (int A = 0; A < Amax; ++A) {
                    for (int j = 0; j < L; ++j) {
                        // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a)
                        // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a)
                        if (j % 256 == 0) hmac_sha256(digest, (uint8_t *)hash_key[A].data(), lam, reinterpret_cast<uint8_t*>(&a), sizeof(int)); 
                        int byteIndex = (j % 256) / 8;
                        int bitIndex = (j % 256) % 8;
                        b[A][0][j] = digest[byteIndex] >> bitIndex & 1;
                    }
                    int B = std::accumulate(b[A][0].begin(), b[A][0].end(), 0); // number of ones in b[A]
                    ell[A] = (1 / M) * (B - L / 2);
                }

                noise[i][a] = std::accumulate(ell.begin(), ell.end(), 0.0);
                err[i] += std::abs(noise[i][a])/d;
            }

            err_ave += err[i] / NumAve;
        }

        // for (const auto& n : noise) {
        //     for (double val : n) {
        //         std::cout << val << " ";
        //     }
        //     std::cout << std::endl;
        // }

        // for (double val : err) {
        //     std::cout << val << " ";
        // }
        // std::cout << std::endl;

        std::cout << err_ave << std::endl;

        if (outFile.is_open()) {
            outFile << eps << "," << err_ave << std::endl;
            outFile.close();
        } 
        else {
            std::cerr << "Error: Unable to open file." << std::endl;
        }
    }

}

TEST_F(BinomialTest, test_FS_MSE)
{
    int d = 625; // number of binomial noises
    double c1 = 2 * D2 * sqrt(2 * log(1.25 / dlt));
    double c2 = 4 / (1 - dlt / 10) * (D2 * 7 * sqrt(2.0) / 4 * sqrt(log(10 / dlt)) + D1*1 / 3)
                  + 4 * (Dinf * (2/3) * log(1.25 / dlt) + Dinf * (2/3) * log(20*d / dlt) * log(10 / dlt));
    double M = floor(eps * (1 / (c1 / sqrt((double)L) + c2 / L)) );
 
    if (M == 0) {
        std::cout << "These privacy budgets cannot be achieved." << std::endl;
    } else {
        // int d = 625; // number of binomial noises
        // double c1 = 2 * D2 * sqrt(2 * log(1.25 / dlt));
        // double c2 = 4 / (1 - dlt / 10) * (D2 * 7 * sqrt(2.0) / 4 * sqrt(log(10 / dlt)) + D1*1 / 3)
        //           + 4 * (Dinf * (2/3) * log(1.25 / dlt) + Dinf * (2/3) * log(20 / dlt) * log(10 / dlt));
        // double M = floor(eps * (1 / (c1 / sqrt((double)L) + c2 / L)) );

        std::string filename = "csv/Binomial_FS_MSE.csv";
        std::ofstream outFile(filename.c_str(), std::ios::app);

        int Amax = static_cast<int>(tgamma(m + 1) / (tgamma(t + 1) * tgamma(m - t + 1)));
        std::vector<std::vector<std::vector<int>>> k(Amax, std::vector<std::vector<int>>(1, std::vector<int>(lam, 0)));
        std::vector<std::vector<double>> noise(NumAve, std::vector<double>(d, 0));
        std::vector<double> err(NumAve, 0); // err is the sum of the absolute values of d laplace noises
        double err_ave = 0;

        srand(time(0)); // seed the random number generator

        std::array<std::uint8_t, 16> hash_key[Amax];

        for (int i = 0; i < NumAve; ++i) {
            for (int A = 0; A < Amax; ++A) {
                for (int l = 0; l < lam; ++l) {
                    k[A][0][l] = rand() % 2; // lam random numbers between 0 and 1
                    hash_key[A][l / 8] |= (k[A][0][i] & 1) << (l % 8);
                }
            }

            for (int a = 0; a < d; ++a) { // a is an input to PRF
                std::vector<std::vector<std::vector<int>>> b(Amax, std::vector<std::vector<int>>(1, std::vector<int>(L, 0)));
                std::vector<double> ell(Amax, 0);

                unsigned char digest[SHA256_DIGEST_LENGTH];
                for (int A = 0; A < Amax; ++A) {
                    for (int j = 0; j < L; ++j) {
                        // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a)
                        // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a)
                        if (j % 256 == 0) hmac_sha256(digest, (uint8_t *)hash_key[A].data(), lam, reinterpret_cast<uint8_t*>(&a), sizeof(int)); 
                        int byteIndex = (j % 256) / 8;
                        int bitIndex = (j % 256) % 8;
                        b[A][0][j] = digest[byteIndex] >> bitIndex & 1;
                    }
                    int B = std::accumulate(b[A][0].begin(), b[A][0].end(), 0); // number of ones in b[A]
                    ell[A] = (1 / M) * (B - L / 2);
                }

                noise[i][a] = std::accumulate(ell.begin(), ell.end(), 0.0);
                err[i] += pow(noise[i][a], 2)/d;
            }

            err_ave += err[i] / NumAve;
        }

        // for (const auto& n : noise) {
        //     for (double val : n) {
        //         std::cout << val << " ";
        //     }
        //     std::cout << std::endl;
        // }

        // for (double val : err) {
        //     std::cout << val << " ";
        // }
        // std::cout << std::endl;

        std::cout << err_ave << std::endl;

        if (outFile.is_open()) {
            outFile << eps << "," << err_ave << std::endl;
            outFile.close();
        } 
        else {
            std::cerr << "Error: Unable to open file." << std::endl;
        }
 
    }

}

TEST_F(BinomialTest, test_UCS_MAE)
{
    int d = 400; // number of binomial noises
    double c1 = 2 * D2 * sqrt(2 * log(1.25 / dlt));
    double c2 = 4 / (1 - dlt / 10) * (D2 * 7 * sqrt(2.0) / 4 * sqrt(log(10 / dlt)) + D1*1 / 3)
                  + 4 * (Dinf * (2/3) * log(1.25 / dlt) + Dinf * (2/3) * log(20*d / dlt) * log(10 / dlt));
    double M = floor(eps * (1 / (c1 / sqrt((double)L) + c2 / L)) );
 
    if (M == 0) {
        std::cout << "These privacy budgets cannot be achieved." << std::endl;
    } else {
        // int d = 400; // number of binomial noises
        // double c1 = 2 * D2 * sqrt(2 * log(1.25 / dlt));
        // double c2 = 4 / (1 - dlt / 10) * (D2 * 7 * sqrt(2.0) / 4 * sqrt(log(10 / dlt)) + D1*1 / 3)
        //           + 4 * (Dinf * (2/3) * log(1.25 / dlt) + Dinf * (2/3) * log(20 / dlt) * log(10 / dlt));
        // double M = floor(eps * (1 / (c1 / sqrt((double)L) + c2 / L)) );


        std::string filename = "csv/Binomial_UCS_MAE.csv";
        std::ofstream outFile(filename.c_str(), std::ios::app);

        int Amax = static_cast<int>(tgamma(m + 1) / (tgamma(t + 1) * tgamma(m - t + 1)));
        std::vector<std::vector<std::vector<int>>> k(Amax, std::vector<std::vector<int>>(1, std::vector<int>(lam, 0)));
        std::vector<std::vector<double>> noise(NumAve, std::vector<double>(d, 0));
        std::vector<double> err(NumAve, 0); // err is the sum of the absolute values of d laplace noises
        double err_ave = 0;

        srand(time(0)); // seed the random number generator

        std::array<std::uint8_t, 16> hash_key[Amax];

        for (int i = 0; i < NumAve; ++i) {
            for (int A = 0; A < Amax; ++A) {
                for (int l = 0; l < lam; ++l) {
                    k[A][0][l] = rand() % 2; // lam random numbers between 0 and 1
                    hash_key[A][l / 8] |= (k[A][0][i] & 1) << (l % 8);
                }
            }

            for (int a = 0; a < d; ++a) { // a is an input to PRF
                std::vector<std::vector<std::vector<int>>> b(Amax, std::vector<std::vector<int>>(1, std::vector<int>(L, 0)));
                std::vector<double> ell(Amax, 0);

                unsigned char digest[SHA256_DIGEST_LENGTH];
                for (int A = 0; A < Amax; ++A) {
                    for (int j = 0; j < L; ++j) {
                        // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a)
                        // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a)
                        if (j % 256 == 0) hmac_sha256(digest, (uint8_t *)hash_key[A].data(), lam, reinterpret_cast<uint8_t*>(&a), sizeof(int)); 
                        int byteIndex = (j % 256) / 8;
                        int bitIndex = (j % 256) % 8;
                        b[A][0][j] = digest[byteIndex] >> bitIndex & 1;
                    }
                    int B = std::accumulate(b[A][0].begin(), b[A][0].end(), 0); // number of ones in b[A]
                    ell[A] = (1 / M) * (B - L / 2);
                }

                noise[i][a] = std::accumulate(ell.begin(), ell.end(), 0.0);
                err[i] += std::abs(noise[i][a])/d;
            }

            err_ave += err[i] / NumAve;
        }

        // for (const auto& n : noise) {
        //     for (double val : n) {
        //         std::cout << val << " ";
        //     }
        //     std::cout << std::endl;
        // }

        // for (double val : err) {
        //     std::cout << val << " ";
        // }
        // std::cout << std::endl;

        std::cout << err_ave << std::endl;

        if (outFile.is_open()) {
            outFile << eps << "," << err_ave << std::endl;
            outFile.close();
        } 
        else {
            std::cerr << "Error: Unable to open file." << std::endl;
        }
 
    }

}

TEST_F(BinomialTest, test_UCS_MSE)
{
    int d = 400; // number of binomial noises
    double c1 = 2 * D2 * sqrt(2 * log(1.25 / dlt));
    double c2 = 4 / (1 - dlt / 10) * (D2 * 7 * sqrt(2.0) / 4 * sqrt(log(10 / dlt)) + D1*1 / 3)
                  + 4 * (Dinf * (2/3) * log(1.25 / dlt) + Dinf * (2/3) * log(20*d / dlt) * log(10 / dlt));
    double M = floor(eps * (1 / (c1 / sqrt((double)L) + c2 / L)) );
 
    if (M == 0) {
        std::cout << "These privacy budgets cannot be achieved." << std::endl;
    } else {
        // int d = 400; // number of binomial noises
        // double c1 = 2 * D2 * sqrt(2 * log(1.25 / dlt));
        // double c2 = 4 / (1 - dlt / 10) * (D2 * 7 * sqrt(2.0) / 4 * sqrt(log(10 / dlt)) + D1*1 / 3)
        //           + 4 * (Dinf * (2/3) * log(1.25 / dlt) + Dinf * (2/3) * log(20 / dlt) * log(10 / dlt));
        // double M = floor(eps * (1 / (c1 / sqrt((double)L) + c2 / L)) );
       
        std::string filename = "csv/Binomial_UCS_MSE.csv";
        std::ofstream outFile(filename.c_str(), std::ios::app);

        int Amax = static_cast<int>(tgamma(m + 1) / (tgamma(t + 1) * tgamma(m - t + 1)));
        std::vector<std::vector<std::vector<int>>> k(Amax, std::vector<std::vector<int>>(1, std::vector<int>(lam, 0)));
        std::vector<std::vector<double>> noise(NumAve, std::vector<double>(d, 0));
        std::vector<double> err(NumAve, 0); // err is the sum of the absolute values of d laplace noises
        double err_ave = 0;

        srand(time(0)); // seed the random number generator

        std::array<std::uint8_t, 16> hash_key[Amax];

        for (int i = 0; i < NumAve; ++i) {
            for (int A = 0; A < Amax; ++A) {
                for (int l = 0; l < lam; ++l) {
                    k[A][0][l] = rand() % 2; // lam random numbers between 0 and 1
                    hash_key[A][l / 8] |= (k[A][0][i] & 1) << (l % 8);
                }
            }

            for (int a = 0; a < d; ++a) { // a is an input to PRF
                std::vector<std::vector<std::vector<int>>> b(Amax, std::vector<std::vector<int>>(1, std::vector<int>(L, 0)));
                std::vector<double> ell(Amax, 0);

                unsigned char digest[SHA256_DIGEST_LENGTH];
                for (int A = 0; A < Amax; ++A) {
                    for (int j = 0; j < L; ++j) {
                        // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a)
                        // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a)
                        if (j % 256 == 0) hmac_sha256(digest, (uint8_t *)hash_key[A].data(), lam, reinterpret_cast<uint8_t*>(&a), sizeof(int)); 
                        int byteIndex = (j % 256) / 8;
                        int bitIndex = (j % 256) % 8;
                        b[A][0][j] = digest[byteIndex] >> bitIndex & 1;
                    }
                    int B = std::accumulate(b[A][0].begin(), b[A][0].end(), 0); // number of ones in b[A]
                    ell[A] = (1 / M) * (B - L / 2);
                }

                noise[i][a] = std::accumulate(ell.begin(), ell.end(), 0.0);
                err[i] += pow(noise[i][a], 2)/d;
            }

            err_ave += err[i] / NumAve;
        }

        // for (const auto& n : noise) {
        //     for (double val : n) {
        //         std::cout << val << " ";
        //     }
        //     std::cout << std::endl;
        // }

        // for (double val : err) {
        //     std::cout << val << " ";
        // }
        // std::cout << std::endl;

        std::cout << err_ave << std::endl;

        if (outFile.is_open()) {
            outFile << eps << "," << err_ave << std::endl;
            outFile.close();
        } 
        else {
            std::cerr << "Error: Unable to open file." << std::endl;
        }
 
    }

}


int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}