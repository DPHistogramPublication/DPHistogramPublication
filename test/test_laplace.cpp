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

class LaplaceTest : public ::testing::Test {
public:
    std::chrono::system_clock::time_point start, end;
    uint8_t test_key[16] = { 0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
                                0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb };
    uint8_t test_aad[16] = { 0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
                                0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab };
    HashEncrypt *test_hash;
    uint8_t out[1024], out2[1024];
    uint32_t outSizeinBytes=0, outSizeinBytes2=0;

    int m = 3, t = 1; // number of servers, threshold
    double eps = 2.0;
    double dlt = pow(10, -8); // privacy budget
    int L = 256; // length of an output of PRF
    int lam = 128; // security
    double D = 2; // sensitivity

    // double alp = exp(-eps / D);
    // int N = (int)ceil((log(pow(dlt, -1)) / eps + 1));
    int NumAve = 100; // number of iterations

protected:
};

TEST_F(LaplaceTest, Laplace_FS_MAE)
{
    int d = 625; // number of laplace noises
    double h = ceil(-log2(1 - exp(-eps/D)));
    double alp = 1 - pow(2, -h);
    int N = (int)ceil(D + (log(d/dlt) / log(1/alp)));
    int Amax = static_cast<int>(tgamma(m + 1) / (tgamma(t + 1) * tgamma(m - t + 1)));

    std::string filename = "csv/Laplace_FS_MAE.csv";
    std::ofstream outFile(filename.c_str(), std::ios::app);

    std::vector<std::vector<std::vector<int>>> k(Amax, std::vector<std::vector<int>>(1, std::vector<int>(lam, 0)));

    std::vector<std::vector<double>> noise(NumAve, std::vector<double>(d, 0));
    std::vector<double> err(NumAve, 0); // err is the sum of the absolute values of d laplace noises
    double err_ave = 0;

    srand(time(0)); // seed the random number generator

    std::array<std::uint8_t, 16> hash_key[Amax];

    for (int i = 0; i < NumAve; ++i) {
        for (int A = 0; A < Amax; ++A) {
            for (int l = 0; l < lam; ++l) {
                k[A][0][l] = rand() % 2; // lam-bit random string
                hash_key[A][l / 8] |= (k[A][0][i] & 1) << (l % 8);
            }
        }

        for (int a = 0; a < d; ++a) { // a is an input to PRF
            double c = 1 + alp - 2 * pow(alp, (N + 1));
            double F0 = (1 - pow(alp, (N + 1))) / c;
            std::vector<std::vector<std::vector<int>>> b(Amax, std::vector<std::vector<int>>(1, std::vector<int>(L, 0)));

            std::vector<double> ell(Amax, 0);

            for (int A = 0; A < Amax; ++A) {
                for (int j = 0; j < L; ++j) {
                    // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a), L-bit pseudorandom string
                    unsigned char digest[SHA256_DIGEST_LENGTH];
                    hmac_sha256(digest, (uint8_t *)hash_key[A].data(), lam, reinterpret_cast<uint8_t*>(&a), sizeof(int)); 
                    b[A][0][j] = digest[0] % 2;
                }

                double u = 0;
                for (int j = 0; j < L; ++j) {
                    u += b[A][0][j] * pow(2, -j - 1);
                }

                if (u < F0) {
                    // ell[A] = -ceil((log(c * u + pow(alp, (N + 1))) / log(alp) - 1) - 1);
                    ell[A] = - floor(log(c * u + pow(alp, (N + 1))) / log(alp));
                } else {
                    // ell[A] = floor(log(c * (1 - u) + pow(alp, (N + 1))) / log(alp));
                    ell[A] = ceil(log(c * (1-u) + pow(alp, (N + 1))) / log(alp) ) - 1;
                }
            }

            noise[i][a] = std::accumulate(ell.begin(), ell.end(), 0.0);
            err[i] += std::abs(noise[i][a])/d;
        }

        err_ave += err[i] / NumAve;
    }

    // for (const auto &n : noise) {
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

TEST_F(LaplaceTest, Laplace_FS_MSE)
{
    int d = 625; // number of laplace noises
    double h = ceil(-log2(1 - exp(-eps/D)));
    double alp = 1 - pow(2, -h);
    int N = (int)ceil(D + (log(d/dlt) / log(1/alp)));
    int Amax = static_cast<int>(tgamma(m + 1) / (tgamma(t + 1) * tgamma(m - t + 1)));

    std::string filename = "csv/Laplace_FS_MSE.csv";
    std::ofstream outFile(filename.c_str(), std::ios::app);

    std::vector<std::vector<std::vector<int>>> k(Amax, std::vector<std::vector<int>>(1, std::vector<int>(lam, 0)));

    std::vector<std::vector<double>> noise(NumAve, std::vector<double>(d, 0));
    std::vector<double> err(NumAve, 0); // err is the sum of the absolute values of d laplace noises
    double err_ave = 0;

    srand(time(0)); // seed the random number generator

    std::array<std::uint8_t, 16> hash_key[Amax];

    for (int i = 0; i < NumAve; ++i) {
        for (int A = 0; A < Amax; ++A) {
            for (int l = 0; l < lam; ++l) {
                k[A][0][l] = rand() % 2; // lam-bit random string
                hash_key[A][l / 8] |= (k[A][0][i] & 1) << (l % 8);
            }
        }

        for (int a = 0; a < d; ++a) { // a is an input to PRF
            double c = 1 + alp - 2 * pow(alp, (N + 1));
            double F0 = (1 - pow(alp, (N + 1))) / c;
            std::vector<std::vector<std::vector<int>>> b(Amax, std::vector<std::vector<int>>(1, std::vector<int>(L, 0)));

            std::vector<double> ell(Amax, 0);

            for (int A = 0; A < Amax; ++A) {
                for (int j = 0; j < L; ++j) {
                    // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a), L-bit pseudorandom string
                    unsigned char digest[SHA256_DIGEST_LENGTH];
                    hmac_sha256(digest, (uint8_t *)hash_key[A].data(), lam, reinterpret_cast<uint8_t*>(&a), sizeof(int)); 
                    b[A][0][j] = digest[0] % 2;
                }

                double u = 0;
                for (int j = 0; j < L; ++j) {
                    u += b[A][0][j] * pow(2, -j - 1);
                }

                if (u < F0) {
                    // ell[A] = -ceil((log(c * u + pow(alp, (N + 1))) / log(alp) - 1) - 1);
                    ell[A] = - floor(log(c * u + pow(alp, (N + 1))) / log(alp));
                } else {
                    // ell[A] = floor(log(c * (1 - u) + pow(alp, (N + 1))) / log(alp));
                    ell[A] = ceil(log(c * (1-u) + pow(alp, (N + 1))) / log(alp) ) - 1;
                }
            }

            noise[i][a] = std::accumulate(ell.begin(), ell.end(), 0.0);
            err[i] += pow(noise[i][a], 2)/d;
        }

        err_ave += err[i] / NumAve;
    }

    // for (const auto &n : noise) {
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

TEST_F(LaplaceTest, Laplace_UCS_MAE)
{
    int d = 400; // number of laplace noises
    double h = ceil(-log2(1 - exp(-eps/D)));
    double alp = 1 - pow(2, -h);
    int N = (int)ceil(D + (log(d/dlt) / log(1/alp)));
    int Amax = static_cast<int>(tgamma(m + 1) / (tgamma(t + 1) * tgamma(m - t + 1)));

    std::string filename = "csv/Laplace_UCS_MAE.csv";
    std::ofstream outFile(filename.c_str(), std::ios::app);

    std::vector<std::vector<std::vector<int>>> k(Amax, std::vector<std::vector<int>>(1, std::vector<int>(lam, 0)));

    std::vector<std::vector<double>> noise(NumAve, std::vector<double>(d, 0));
    std::vector<double> err(NumAve, 0); // err is the sum of the absolute values of d laplace noises
    double err_ave = 0;

    srand(time(0)); // seed the random number generator

    std::array<std::uint8_t, 16> hash_key[Amax];

    for (int i = 0; i < NumAve; ++i) {
        for (int A = 0; A < Amax; ++A) {
            for (int l = 0; l < lam; ++l) {
                k[A][0][l] = rand() % 2; // lam-bit random string
                hash_key[A][l / 8] |= (k[A][0][i] & 1) << (l % 8);
            }
        }

        for (int a = 0; a < d; ++a) { // a is an input to PRF
            double c = 1 + alp - 2 * pow(alp, (N + 1));
            double F0 = (1 - pow(alp, (N + 1))) / c;
            std::vector<std::vector<std::vector<int>>> b(Amax, std::vector<std::vector<int>>(1, std::vector<int>(L, 0)));

            std::vector<double> ell(Amax, 0);

            for (int A = 0; A < Amax; ++A) {
                for (int j = 0; j < L; ++j) {
                    // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a), L-bit pseudorandom string
                    unsigned char digest[SHA256_DIGEST_LENGTH];
                    hmac_sha256(digest, (uint8_t *)hash_key[A].data(), lam, reinterpret_cast<uint8_t*>(&a), sizeof(int)); 
                    b[A][0][j] = digest[0] % 2;
                }

                double u = 0;
                for (int j = 0; j < L; ++j) {
                    u += b[A][0][j] * pow(2, -j - 1);
                }

                if (u < F0) {
                    // ell[A] = -ceil((log(c * u + pow(alp, (N + 1))) / log(alp) - 1) - 1);
                    ell[A] = - floor(log(c * u + pow(alp, (N + 1))) / log(alp));
                } else {
                    // ell[A] = floor(log(c * (1 - u) + pow(alp, (N + 1))) / log(alp));
                    ell[A] = ceil(log(c * (1-u) + pow(alp, (N + 1))) / log(alp) ) - 1;
                }
            }

            noise[i][a] = std::accumulate(ell.begin(), ell.end(), 0.0);
            err[i] += std::abs(noise[i][a])/d;
        }

        err_ave += err[i] / NumAve;
    }

    // for (const auto &n : noise) {
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

TEST_F(LaplaceTest, Laplace_UCS_MSE)
{
    int d = 400; // number of laplace noises
    double h = ceil(-log2(1 - exp(-eps/D)));
    double alp = 1 - pow(2, -h);
    int N = (int)ceil(D + (log(d/dlt) / log(1/alp)));
    int Amax = static_cast<int>(tgamma(m + 1) / (tgamma(t + 1) * tgamma(m - t + 1)));

    std::string filename = "csv/Laplace_UCS_MSE.csv";
    std::ofstream outFile(filename.c_str(), std::ios::app);

    std::vector<std::vector<std::vector<int>>> k(Amax, std::vector<std::vector<int>>(1, std::vector<int>(lam, 0)));

    std::vector<std::vector<double>> noise(NumAve, std::vector<double>(d, 0));
    std::vector<double> err(NumAve, 0); // err is the sum of the absolute values of d laplace noises
    double err_ave = 0;

    srand(time(0)); // seed the random number generator

    std::array<std::uint8_t, 16> hash_key[Amax];

    for (int i = 0; i < NumAve; ++i) {
        for (int A = 0; A < Amax; ++A) {
            for (int l = 0; l < lam; ++l) {
                k[A][0][l] = rand() % 2; // lam-bit random string
                hash_key[A][l / 8] |= (k[A][0][i] & 1) << (l % 8);
            }
        }

        for (int a = 0; a < d; ++a) { // a is an input to PRF
            double c = 1 + alp - 2 * pow(alp, (N + 1));
            double F0 = (1 - pow(alp, (N + 1))) / c;
            std::vector<std::vector<std::vector<int>>> b(Amax, std::vector<std::vector<int>>(1, std::vector<int>(L, 0)));

            std::vector<double> ell(Amax, 0);

            for (int A = 0; A < Amax; ++A) {
                for (int j = 0; j < L; ++j) {
                    // b[A][0][j] = rand() % 2; // b[A] = PRF(k[A], a), L-bit pseudorandom string
                    unsigned char digest[SHA256_DIGEST_LENGTH];
                    hmac_sha256(digest, (uint8_t *)hash_key[A].data(), lam, reinterpret_cast<uint8_t*>(&a), sizeof(int)); 
                    b[A][0][j] = digest[0] % 2;
                }

                double u = 0;
                for (int j = 0; j < L; ++j) {
                    u += b[A][0][j] * pow(2, -j - 1);
                }

                if (u < F0) {
                    // ell[A] = -ceil((log(c * u + pow(alp, (N + 1))) / log(alp) - 1) - 1);
                    ell[A] = - floor(log(c * u + pow(alp, (N + 1))) / log(alp));
                } else {
                    // ell[A] = floor(log(c * (1 - u) + pow(alp, (N + 1))) / log(alp));
                    ell[A] = ceil(log(c * (1-u) + pow(alp, (N + 1))) / log(alp) ) - 1;
                }
            }

            noise[i][a] = std::accumulate(ell.begin(), ell.end(), 0.0);
            err[i] += pow(noise[i][a], 2)/d;
        }

        err_ave += err[i] / NumAve;
    }

    // for (const auto &n : noise) {
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


int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}