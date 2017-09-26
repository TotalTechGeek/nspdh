#include "nspdh_utilities.hpp"
#include <boost/math/special_functions/prime.hpp>

namespace nspdh 
{
    #define generateIt(size) gen() >> ((8192*2) - size);
   
    using namespace std;

    using namespace boost::random;
    using namespace boost::math; 
    using namespace boost::multiprecision;
    
    // Defines the available generators
    static generator_type gen(time(0));
    static generator_type2 gen2(time(0));

    // Finds the bitsize. 
    int blog2(cpp_int val)
    {   
        return msb(val)+1;
    }

    // Tests whether the given cpp_int is prime or not.
    // It print out a "." when a potential prime is found. This is to
    // give it more ssl-like behavior.
    char fastPrimeC(const cpp_int& v)
    {   
        // Iterate over a small list of primes to give a tiny boost to the primality checking
        // This is mainly used so we can output a '.' 
        for(int i = 1; i <= blog2(v)/1.5f + 1; i++)
        {
            if(v == prime(i)) return 1;
            if(!(v % prime(i))) return 0; 
        }

        // Print out a dot to indicate that it may have potentially found a prime value.
        cout << "." << flush;

        // Miller Rabin Test Section, seems to optimize better than the built in Boost MR Test.
        cpp_int s = v - 1;
        while (!(s & 1)) s >>= 1;
        for (int i = 0; i < 9; i++)
        {
            cpp_int a = gen2(), temp = s;
            cpp_int mod = powm(a, temp, v);
            
            while (!(mod == 1 || temp == v - 1 || mod == v - 1))
            {
                mod = powm(mod, 2, v);
                temp <<= 1;
            }
            
            if (!(temp & 1) && mod != v-1)
            {
                return 0;
            }
        }

        return 1;
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
    char checkGenerator(const cpp_int& proposed, const cpp_int& modPrime, const cpp_int& phPrime, int smallVal)
    {
        vector<int> facts = factor(smallVal);
        cpp_int tot = modPrime - 1;

        // Computes g^(totient/2) 
        if(powm(proposed,tot/2,modPrime) == 1) return 0;
        
        // Computes g^(totient/pohlig-hellman prime factor)
        if(powm(proposed, tot/phPrime, modPrime) == 1) return 0;

        // Computes g^(totient/p_i), which is the generator raised to the power of the totient divided by each unique prime factor.
        for(int i = 0; i < facts.size(); i++)
        {
            if(powm(proposed, tot/facts[i], modPrime) == 1) return 0; 
        }

        // This was a primitive root.
        return 1;
    }


    // Checks the generator, even if it's a quadratic residue. This is for the verification function.
    char checkGeneratorInclusive(const cpp_int& proposed, const cpp_int& modPrime, const cpp_int& phPrime, int smallVal)
    {
        // Checks if it is a Quadratic Residue.
        if(powm(proposed, (modPrime-1)/2, modPrime) == 1)
        {   
            // has second bit flag that it was a quadratic.
            return 3; // binary = 11
        }
        
        return checkGenerator(proposed, modPrime, phPrime, smallVal);
    }

    // Finds the number of generators of a cyclic group (totient of totient). 
    // Totient(modPrime) * product of each factor (1 - 1/p_i),
    // Totient(modPrime) * product of each factor ((p_i-1)/p_i)
    cpp_int numberOfGenerators(const cpp_int& modPrime, const cpp_int& phPrime, int smallVal)
    {
        cpp_int val = modPrime - 1;

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
    cpp_int generatePrime(int size, volatile char* completionStatus)
    {            
        // Generates a random value.
        cpp_int primeVal = generateIt(size);
                
        // Enforces size restctions (and that it is odd)
        primeVal |= (((cpp_int)1) << (size-1)) | 1;
                    
        while(!fastPrimeC(primeVal))
        {
            // If a Pohlig-Hellman Prime has been found by another thread, sleep. 
            while(*completionStatus == NSPDH_POHLIG_FOUND) Sleep(2000);
            
            // If a Modulus Prime was found, just quit.
            if(*completionStatus == NSPDH_MODULUS_FOUND) break;
            
            // If the value wasn't prime, skip ahead to the next odd integer.
            primeVal += 2;
        }

        return primeVal;
    }


    // Generates a Prime Tuple, and intentionally attempts to "maximize" its Pohlig-Hellman strength.
    // While this is not technically necessary (not a requirement of DSA), I think that it is probably worth it.
    // One thing to consider is that since the added Prime Factors are unknown, the GFNS (for factorization) must be applied.
    cpp_int generatePrimeTuple(int size, cpp_int base, volatile char* completionStatus)
    {
        // Generates a random value.
        cpp_int offset, enhancer;
        int count(65536), retries(0);

        while(true)
        {
            // Used in case there are no results to be had. 
            if(count++ & 65536)
            {
                if(++retries == 10) return 0;
                
                offset = gen2();
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
            cpp_int shiftedOffset = offset;
            
            // Shifts the offset.
            while(blog2(shiftedOffset*base*enhancer + 1) < size) 
            {
                shiftedOffset <<= 1;

                //Gives it some extra entropy.
                shiftedOffset |= (gen2() & 1);
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