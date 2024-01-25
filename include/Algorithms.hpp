#pragma once

#include <iostream>
#include <string>
#include <boost/integer/common_factor_rt.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/gmp.hpp>
#include <time.h>

using namespace std;
using namespace boost::random;
using namespace boost::multiprecision;
namespace mp = boost::multiprecision;
// typedef mp::cpp_int Int;
typedef mp::mpz_int Int;

static boost::random::mt19937 gen(clock());

class Algorithms {
public:
    Algorithms(){};
    ~Algorithms(){};

    template <unsigned int B>
    static inline Int genSafePrime(unsigned int it) {
        mt11213b base_gen(clock());
        independent_bits_engine<mt11213b, B, Int> gen(base_gen);
        mt19937 gen2(clock());
        for(;;) {
            Int n = gen();
            if (miller_rabin_test(n, it, gen2)) {
                if (miller_rabin_test((n-1)/2, it, gen2)) {
                    return n;
                }
            }
        }
    }

    static inline void seedRNG() {
        gen.seed(static_cast<uint32_t>(std::time(0)));
    }

    static inline Int genRandomInt(Int lb, Int ub) {
        boost::random::uniform_int_distribution<Int> dist(lb, ub);
        return dist(gen);
    }

    static inline std::pair<Int, std::pair<Int, Int> > extentedEuclid(Int a, Int b) {
        Int x=1, y=0;
        Int xLast=0, yLast=1;
        Int q, r, m, n;
        while (a != 0) {
            q = b/a;
            r = b%a;
            m = xLast - q*x;
            n = yLast - q*y;
            xLast = x; yLast = y;
            x = m; y = n;
            b = a; a = r;
        }
        return std::make_pair(b, std::make_pair(xLast, yLast));
    }

    static inline Int inverse(Int a, Int m) {
        return (extentedEuclid(a, m).second.first + m) % m;
    }

    template <unsigned int B>
    static inline std::vector<Int> genRandomVector(unsigned int sz) {
        Algorithms::seedRNG();
        std::vector<Int> vec;

        Int p = Algorithms::genSafePrime<B>(sz);

        vec.reserve(sz);
        for(uint32_t i=0; i<sz; ++i) {
            Int r = genRandomInt(2, p-1);
            vec.push_back(r);
        }
        return vec;
    }

};