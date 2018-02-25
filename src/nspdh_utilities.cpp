#include "nspdh_utilities.hpp"
#include <climits>
#include <iostream>
#include "../cryptopp/osrng.h"

namespace nspdh 
{

   
    using namespace std;


    #if defined(_WIN32) || defined(_WIN64)
    #else
    void Sleep(int x)
    {
        // Honestly, 1024 and 1000 are close enough, so that's why I'm using that.
        // Worst case scenario is that it takes an extra 24ms for a thread to wake up. 
        // This will hardly be a noticeable factor in the scheme of things. 
        usleep(x << 10); 
    }
    #endif
    
    // Finds the bitsize. 
    int blog2(Integer val)
    {   
        return val.BitCount();
    }

    static vector<long long> primeCache;

    bool isprime(long long x)
    {
        if(primeCache.size() == 0)
        {
            primeCache.push_back(2);
            primeCache.push_back(3);
        }

        long long q = primeCache[primeCache.size() - 1];
        while(q*q <= x)
        {
            q += 2;
            if(isprime(q)) primeCache.push_back(q);
        } 

        int z = 0;
        while(primeCache[z]*primeCache[z] <= x)
        {
            if(!(x % primeCache[z])) return false;
            
            z++;
        }
        return true;
    }

    long long prime(int x)
    {   
        return primeCache[x];
    }


    // Tests whether the given Integer is prime or not.
    // It print out a "." when a potential prime is found. This is to
    // give it more ssl-like behavior.
    char fastPrimeC(const Integer& v, long long *cache, long long by)
    {   

        int primeMax = blog2(v)/1.5f + 1;
        if(primeMax >= NSPDH_TRIAL_DIVISIONS) primeMax = NSPDH_TRIAL_DIVISIONS;
        if (cache)
        {
            bool cacheMade = false, returnEarly = false;
            if(cache[0] == -1 || cache[0] == -2)
            {
                primeMax = NSPDH_TRIAL_DIVISIONS;
                // Iterate over a small list of primes to give a tiny boost to the primality checking
                // This is mainly used so we can output a '.' 
                for(int i = 1; i < primeMax; i++)
                {
                    if(v == prime(i)) 
                    {
                        cache[0] = -1;
                        return 1;
                    }

                    
                    cache[i] = v % prime(i);
                    if(cache[0] == -1) cache[i] = (prime(i) - cache[i]) % prime(i);
                    else cache[i] *= 2;
                }
            }

            // this is just a hack for now.
            if (cache[0] == -2) return true;     

            // says that the cache has been established.
            cache[0] = 0;       

            if(by)
            {
                for(int i = 1; i <= primeMax; i++)
                {
                    if((cache[i] * by + 1) % prime(i) == 0) return false;
                }
            }
            else
            {
                for(int i = 1; i <= primeMax; i++)
                {
                    if(cache[i] <= 0) 
                    {
                        if(cache[i] == 0)
                            returnEarly = true;
                        cache[i] += prime(i);
                    }
                }
                
                // Written in such a way that SIMD should optimize here.
                for(int i = 1; i <= primeMax; i++)
                {
                    cache[i] -= 2;
                }
            }

            if (returnEarly) return 0;

        }
        else
        {
            // Iterate over a small list of primes to give a tiny boost to the primality checking
            // This is mainly used so we can output a '.' 
            for(int i = 1; i <= primeMax; i++)
            {
                if(v == prime(i)) return 1;
                if(!(v % prime(i))) return 0; 
            }
        }

        // Print out a dot to indicate that it may have potentially found a prime value.
        cout << "." << flush;
        
       	// Optimization based on a paper I will cite at a later date.
        int trialCount = 9;
        if(blog2(v) >= 2000) trialCount = 3;
        else if(blog2(v) >= 1024) trialCount = 6;
        
        CryptoPP::AutoSeededRandomPool asrp;
        return IsStrongProbablePrime(v, 3) && IsStrongLucasProbablePrime(v) && RabinMillerTest(asrp, v, trialCount);
    }


    // Finds all the [unique] prime factors of a small integer. 
    vector<int> factor(int val)
    {
        int c = 0;
        vector<int> res;
        
        // While the current prime is less than or equal to the value . . . 
        while(prime(c)*prime(c) <= val)
        {
            // If the number is divisible by the prime
            if(!(val % prime(c)))
            {
                // Push the prime into the collection
                res.push_back(prime(c));

                // Completely remove the factor from the value.
                while(!(val % prime(c)))
                {
                    val /= prime(c);
                }
            }

            // Go to the next prime.
            c++;
        }

        // If the value isn't 1, then the current value is prime.
        if(val != 1)
        {
            res.push_back(val);
        }

        
        // return the collection
        return res;
    }

    // Checks whether a given generator is valid primitive root or not.
    char checkGenerator(const Integer& proposed, const Integer& modPrime, const Integer& phPrime, int smallVal)
    {
        vector<int> facts = factor(smallVal);
        Integer tot = modPrime - 1;

        // Computes g^(totient/2) 
        if(a_exp_b_mod_c(proposed,tot/2,modPrime) == 1) return 0;
        
        // Computes g^(totient/pohlig-hellman prime factor)
        if(a_exp_b_mod_c(proposed, tot/phPrime, modPrime) == 1) return 0;

        // Computes g^(totient/p_i), which is the generator raised to the power of the totient divided by each unique prime factor.
        for(int i = 0; i < facts.size(); i++)
        {
            if(a_exp_b_mod_c(proposed, tot/facts[i], modPrime) == 1) return 0; 
        }

        // This was a primitive root.
        return 1;
    }


    // Checks the generator, even if it's a quadratic residue. This is for the verification function.
    char checkGeneratorInclusive(const Integer& proposed, const Integer& modPrime, const Integer& phPrime, int smallVal)
    {
        // Checks if it is a Quadratic Residue.
        if(a_exp_b_mod_c(proposed, (modPrime-1)/2, modPrime) == 1)
        {   
            // has second bit flag that it was a quadratic.
            return 3; // binary = 11
        }
        
        return checkGenerator(proposed, modPrime, phPrime, smallVal);
    }

    // Finds the number of generators of a cyclic group (totient of totient). 
    // Totient(modPrime) * product of each factor (1 - 1/p_i),
    // Totient(modPrime) * product of each factor ((p_i-1)/p_i)
    Integer numberOfGenerators(const Integer& modPrime, const Integer& phPrime, int smallVal)
    {
        Integer val = modPrime - 1;

        // Unnecessary instruction left commented for consistency. 
        // val *= 1; 
        val /= 2; 

        val *= phPrime-1; 
        val /= phPrime; 

        // Gets all the factors of the offset :)
        vector<int> facts = factor(smallVal);

        // Iterates over all the factors.
        for(int i = 0; i < facts.size(); i++)
        {
            // Skips 2 as a factor, since we already did it.
            if(facts[i] == 2) continue;
            val *= facts[i]-1;
            val /= facts[i]; 
        }
        
        return val; 
    }


    // Generates a prime value of the requested size.
    // While not preferable, the volatile char* is included to allow the function to sleep, yielding to other threads. 
    Integer generatePrime(int size, volatile char* completionStatus)
    {
        CryptoPP::AutoSeededRandomPool asrp;            
        // Generates a random value.
        Integer primeVal;
        primeVal.Randomize(asrp, size);
        
                
        // Enforces size restctions (and that it is odd)
        primeVal |= (((Integer)1) << (size-1)) | 1;

        long long *cache = new long long[NSPDH_TRIAL_DIVISIONS]();
        cache[0] = -1;
                    
        while(!fastPrimeC(primeVal, cache))
        {
            // If a Pohlig-Hellman Prime has been found by another thread, sleep. 
            while(*completionStatus == NSPDH_POHLIG_FOUND) Sleep(2000);
            
            // If a Modulus Prime was found, just quit.
            if(*completionStatus == NSPDH_MODULUS_FOUND) break;
            
            // If the value wasn't prime, skip ahead to the next odd integer.
            primeVal += 2;
        }

        delete [] cache;

        return primeVal;
    }


    // Generates a Prime Tuple, and intentionally attempts to "maximize" its Pohlig-Hellman strength.
    // While this is not technically necessary (not a requirement of DSA), I think that it is probably worth it.
    // One thing to consider is that since the added Prime Factors are unknown, the GFNS (for factorization) must be applied.
    Integer generatePrimeTuple(int size, Integer base, volatile char* completionStatus)
    {
        // Generates a random value.
        Integer offset, enhancer, z;
        CryptoPP::AutoSeededRandomPool asrp;
        int count(65536), retries(0);

        while(true)
        {
            // Used in case there are no results to be had. 
            if(count++ & 65536)
            {
                if(++retries == 10) return 0;
                
                offset.Randomize(asrp, 256);
                enhancer = 2;

                // Attempts to boost the known strength of the tuple.
                if(blog2(base) < 1024 && (size - blog2(base) - 1024) >= 256)
                {
                    enhancer = 2*generatePrime(1024, completionStatus);
                }
                else    
                // Attempts to boost it again, just smaller.
                if(blog2(base) < 512 && (size - blog2(base) - 512) >= 256)
                {
                    enhancer = 2*generatePrime(512, completionStatus);
                }
                else 
                // Attempts to boost it again, just smaller.
                if(blog2(base) < 256 && (size - blog2(base) - 256) >= 256)
                {
                    enhancer = 2*generatePrime(256, completionStatus);
                } 
    
                count = 0;
            }

            // If a Pohlig-Hellman Prime has been found by another thread, sleep. 
            while(*completionStatus == NSPDH_POHLIG_FOUND) Sleep(2000);
            
            // If a Modulus Prime was found, just quit.
            if(*completionStatus == NSPDH_MODULUS_FOUND) break;
        
            // This is used to place the randomly generated offset into a range where it can create the correct bit size. 
            Integer shiftedOffset = offset;
            
            // Shifts the offset.
            while(blog2(shiftedOffset*base*enhancer + 1) < size) 
            {
                shiftedOffset <<= 1;

                z.Randomize(asrp, 2);
                //Gives it some extra entropy.
                shiftedOffset |= (z & 1);
            }

            // If it created a value of a correct size,
            if(blog2(shiftedOffset*base*enhancer + 1) == size)
        
            // check if it is prime and return it if it is. 
            if(fastPrimeC(shiftedOffset*base*enhancer + 1)) return base*shiftedOffset*enhancer + 1;
            offset--;
        }

        // Used just in case.
        return 0;
    }
}
