#ifndef _NSPDH_UTIL_ 
#define _NSPDH_UTIL_


#include "../cryptopp/integer.h"
#include "../cryptopp/nbtheory.h"

#include <vector>
#include "portable_mutex.hpp"

namespace nspdh 
{
    // Included as a workaround for Unix/Windows compatibility.
    #if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
    #else
    #include <unistd.h>
    void Sleep(int x);
    #endif

    // This is included as a workaround for older versions of g++.
    #ifndef nullptr 
    #define nullptr NULL
    #endif

    #define NSPDH_TRIAL_DIVISIONS 40000

    #define NSPDH_SEARCH 0
    #define NSPDH_POHLIG_FOUND  1
    #define NSPDH_MODULUS_FOUND 2
    #define NSPDH_FREEZE 3
    #define NSPDH_DHPARAM (1<<2)
    #define NSPDH_DSAPARAM (2<<2)
    
    using CryptoPP::Integer;
    
    // Defines the available functions
    int blog2(Integer val);
    bool isprime(long long x);
    long long prime(int x);
    char fastPrimeC(const Integer& v, long long *cache = nullptr, long long by = 0);
    std::vector<int> factor(int val);
    char checkGenerator(const Integer& proposed, const Integer& modPrime, const Integer& phPrime, int smallVal);
    char checkGeneratorInclusive(const Integer& proposed, const Integer& modPrime, const Integer& phPrime, int smallVal);
    Integer numberOfGenerators(const Integer& modPrime, const Integer& phPrime, int smallVal);
    Integer generatePrime(int size, volatile char* completionStatus);
    Integer generatePrimeTuple(int size, Integer base, volatile char* completionStatus);
}
#endif
