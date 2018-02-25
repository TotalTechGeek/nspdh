#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <omp.h>

#include "../cryptopp/integer.h"
#include "../cryptopp/nbtheory.h"

#include "../cryptopp/osrng.h"

#include "portable_mutex.hpp"
#include "nspdh_utilities.hpp"
#include "nspdh_io.hpp"

using CryptoPP::Integer;

// Written by Jesse Daniel Mitchell (2017). 
// To-do: 
// Finish up splitting up the code (cpp and hpp files), and clean it up slightly more. [UH]
// I'll also come up with a reasonable standard format for exporting some of these values in a neutral way, either JSON or XML. [H]
// * This will support both Tri-Prime Tuples and regular DH Parameters. I could also modify it to allow really condensed signatures. (~60 Bytes to encode any set of parameters).   
// I need to consider whether I want to add support for decoding OpenSSL Files or not, (unber), for verification. [UL]
// * If I do that though, I'll need to add new code to the unber code, to support doing stuff from buffers.
// ** I think I've settled on not converting backwards using NSPDH. The high priority target will be coming up with a neutral format to convert from, with all relevant information.
// Add verification for DSA Parameters [M]
// Consider dropping the current exported XML Format, switch to your own format that will be easy to convert from. [H]
// Consider OpenSSH Moduli Files [H]

// Eventually I'll advocate for Discrete Log Cryptography over RSA, using Tuples and NSPs. 
// It's much cheaper, and can do Public Key Crypto. (I don't think Ephemeral is important). 
// Also parameters don't necessarily require entropy, allowing efficient encoding using CSPRNGs.
// While RSA would have an advantage (size of encrypted file), the differences could be mitigated 
// using CSPRNG Encoding. example format:
// [32 Byte Entropy Seed][1 Byte CSPRNG Configuration][1 Byte Hash Algorithm Configuration][2 Byte Tuple Size][2 Byte Pohlig Size][1 Byte "Moment" Count (Tuple)][1 Byte "Moment" Count (Pohlig)][4 Byte Offset (Pohlig)][4 Byte Offset (Modulus)]
// 32 + 1 + 1 + 1 + 1 + 4 + 4 + 2 + 2 = 48 Bytes to encode parameters completely.

// Also, it's quite easy to implement Ephemeral Public Key Cryptography using Discrete Logs, 
// though I don't see how it'd be necessary.
// Step 1   - s1 = Compute (pub_a) ^ priv_b mod p
// Step 2*  - s2 = Compute a standard Ephemeral Diffie-Hellman Key Exchange (could even take place on smaller params, not just the same parameters). 
// Step 3** - Combine s1 and s2. 

// *  This might theoretically be useful for semi-ephemeral key exchanges. Just rotate out a secondary public key.
// ** For step 3, I originally would've recommended multiplying the shared secrets together and moduloing (if the same parameters were used), but it's highly unnecessary.

// Alternate Scheme :
// The point of Ephemeral Public Key Crypto in this situation is to provide a layer of PFS on top of Authentication.
// It would probably be better to just perform an ephemeral key exchange and create a secure hash of the shared key 
// combined with a time stamp, and sign it. This is what we already do with DHE-DSA. 

using namespace std;


using namespace nspdh;


// Displays the flags possible.
// Needs more verbosity.
void displayHelp(char* exeName, bool verbose = false)
{
    // Basic Help
    cout << exeName << " [<bitsize>|-help|-verify <filename>] [-out <fileName>] [args]" << endl;
    
    // Attempts to give some documentation of the options.
    // Todo: Clarify -tolerate, and include the shortened tags.
    if(verbose)
    {
        cout << "-randomize" << "\tRandomizes the generator" << endl;
        cout << "-quadratic" << "\tExports a Quadratic Residue Generator in the out file. (Wei Dai Recommendation)" << endl;
        cout << "-smallest"  << "\tExports the smaller of the two generators (between Quadratic Residue and Primitive Root)" << endl;
        cout << "-multiple"  << "\tSearches for all associated NSPs associated with the Pohlig-Hellman Prime." << endl;
        cout << "-max"  << "\t\tSpecifies the maximum number of NSPs to find associated with the Pohlig-Hellman prime. (-multiple required)." << endl;
        cout << "-n <value>" << "\tSets the restricted range for finding NSPs." << endl;
        cout << "-bn <value>" << "\tSets the restricted range (in bits) for finding NSPs." << endl;
        cout << "-8" << "\t\tForces the Modulus length to be divisible by 8." << endl;
        cout << "-verify <file>" << "\tVerifies the parameters in a file. OpenSSL Formats are not supported (yet)." << endl;
        cout << "-hex" << "\t\tPrints out prime number and generator output in hex." << endl;
        cout << "-use <number>" << "\tAttempts to use a number input into it as the Pohlig-Hellman prime (base 10, or base 16 if -hex is used before this flag)." << endl;
        cout << "-tuple <size>" << "\tFinds a smaller prime of the specified size that will be related to the Pohlig-Hellman prime, creating a Tri-Prime Tuple. For use with signatures." << endl;
        cout << "-out <fileName>" << "\tExports the parameters to a file." << endl;
        #ifdef LINKASN1C
        cout << "-der" << "\t\tExports an OpenSSL-compatible .der file." << endl;
        cout << "-pem" << "\t\tExports an OpenSSL-compatible .pem file. (Experimental)" << endl;
        #endif
        cout << flush;
    }
}

// This is used as a hack to allow me to decide whether I want to return something or not.
static Integer hack; 

// Verifier function.
// Needs refactoring and some expansion. 
// It works, but I need to make it so that it's a pure function without output.
// Note that this is not proper XML Parsing, but it is not completely necessary.
// I am relying on the user to pass in valid input. 
char verifier(char* p, int range = 4096, int trials = 10, bool hex = false, bool verifyDC = false, Integer& rmodulus = hack, Integer& rgenerator = hack)
{
    char results[3];
    int i(0), N(1);

    // Used for hex conversion
    char b(0);

    // Used for validation.
    Integer modulus, pohlig, generator;


    if(verifyDC)
    {
        int16_t len1, len2; 
        
        len1 = *(int16_t*)p;
        p += sizeof(int16_t);

        len2 = *(int16_t*)p;
        p += sizeof(int16_t);

        modulus.Decode((unsigned char*)p, len1);
        p += len1;

        generator.Decode((unsigned char*)p, len2);
    }
    else
    {
        // XML File Format Thingy.
        for(int j = 0; j < 2; j++) 
        {
            // Skips to the first character after the first '>'
            while(p[i++] != '>'); 
            // Skips to the first character after the second '>'
            while(p[i++] != '>');
            
            // Checks if we're currently on a hex value.
            while(p[i] == '&')
            {
                // Skips to the first character after the 'x'.
                while(p[i++] != 'x');

                // Convert two digit hex to decimal.
                // Top 4 Bits 
                if(p[i] >= '0' && p[i] <= '9')
                b = (p[i++] - '0')*16;
                else
                b = (p[i++] - 'a' + 10)*16;

                // Bottom 4 bits.
                if(p[i] >= '0' && p[i] <= '9')
                b += (p[i++] - '0');
                else
                b += (p[i++] - 'a' + 10);
                // End hex conversion.
                
                // Consume the hex value. 
                generator <<= 8;
                generator |= (unsigned char)b; 

                // Go onto the next hex value or end.
                i++;    
            }

            // This is a shortcut done to shorten the code. 
            if(!j)
            {
                modulus = generator;
                generator = 0;
            }
        }
    }

    

    // Prints out the supposed Modulus Prime.
    cout << "Modulus Prime (" << blog2(modulus) << " bits): " << (hex ? std::hex : std::dec) << modulus << std::dec << endl;
    cout << endl;
    
    // Used to compute the actual Pohlig.
    pohlig = (modulus - 1)/2;
    int c(0);
    
    // Factor out every prime within range.
    while (c < NSPDH_TRIAL_DIVISIONS && N <= range && prime(c) <= range)
    {
        while(!(pohlig % prime(c))) 
        {
            pohlig /= prime(c);
            N *= prime(c);
        }
        c++;
    }

    // Prints out the computed Pohlig-Hellman prime.
    cout << "Pohlig-Hellman Prime (" << blog2(pohlig) << " bits): " << (hex ? std::hex : std::dec) << pohlig << std::dec << endl;
    cout << endl << "N: " << N << endl;

    CryptoPP::AutoSeededRandomPool asrp; 
    // A silly (but simple) way to parallelize this process.
    #pragma omp parallel for 
    for (int branch = 0; branch < 3; branch++)
    {
        if (branch == 0) results[branch] = RabinMillerTest(asrp, modulus, trials);
        else if(branch == 1) results[branch] = RabinMillerTest(asrp, pohlig, trials);
        else if(branch == 2) results[branch] = checkGeneratorInclusive(generator, modulus, pohlig, N);
    }

    // Sets the generator to zero in case of some false positive.
    if(!(results[0] && results[1])) results[2] = 0;
    
    // Prints out the generator.
    cout << "Generator: " << (hex ? std::hex : std::dec) << generator << " ";
    
    // Outputs if it was quadratic.
    if(results[2] & 2) cout << "(Quadratic Residue)"; 
    
    // Print out verification results.
    cout << endl << endl;
    cout << ((results[0]) ? "Modulus Verified" : "Modulus Invalid") << endl;
    cout << ((results[1]) ? "Pohlig Verified" : "Pohlig Invalid (Consider expanding the tolerated range?)") << endl;
    
    // We can't verify the generator without knowing the Pohlig-Hellman prime, so we create a requirement for it.
    if(results[1])
    cout << ((results[2]) ? "Generator Verified" : "Generator Not Verified") << endl;

    // Used to return these parameters.
    rgenerator = generator;
    rmodulus = modulus;

    char res = 0 | (results[0]) | (results[1] << 1) | (results[2] << 2);
    return res;
}

int main(int argc, char **args)
{
    // Todo: Create a C-Style struct for these parameters.
    // This is more of a collection than a class, 
    // so a struct is more reasonable.

    // Define some generator constants.
    const int NSPDH_GENERATOR_PRIMITIVE_ROOT = 0;
    const int NSPDH_GENERATOR_QUADRATIC = 1;
    const int NSPDH_GENERATOR_SMALLEST = 2;

    isprime(1024ll*1024ll*1024ll*1024ll * 4);

    // Flags for the Program //
    int size(2048);
    int maxModuli(0); 
    int tuple(0);
    char convert = 0;
    bool multiple(false);
    bool hex(false);
    bool verifyDC(false);
    bool divisibleBy8(false);
    bool randomizeGenerator(false);
    char generatorMode(NSPDH_GENERATOR_PRIMITIVE_ROOT);
    char *outFile = nullptr;
    char *verify  = nullptr;
    long long maxN(4096ll | (1ll << 40));
    Integer requestPrime("0");
    // End Flags //

    // Mutex for adding the parameters.
    Mutex mut; 

    // Simple command parser.
    for(int i = 1; i < argc; i++)
    {
        #ifdef LINKASN1C
        // Converts the parameters to the .der format OpenSSL understands.
        if(!strcmp(args[i], "-der")) convert |= 1;
        else

        // Converts the parameters to the .pem format OpenSSL understands. (Experimental)
        if(!strcmp(args[i], "-pem")) convert |= 2;
        else
        #endif

        // Converts the parameters to the .dh format DiscreteCrypt understands.
        if(!strcmp(args[i], "-dc")) convert |= 4;
        else

        // Sets the output to be hexadecimal.
        if(!strcmp(args[i], "-hex")) hex = true;
        else

        // Displays the verbose version of the help.
        if(!strcmp(args[i], "-h") || !strcmp(args[i], "-help")) 
        {
            displayHelp(args[0], true);
            return 0;
        }
        else

        // Attempts to use this value as the prime (and find one near it).
        if(!strcmp(args[i], "-use") || !strcmp(args[i], "-u") || !strcmp(args[i], "-in")) 
        { 
            string p = (args[++i]);
            if(hex)
            {
                if(p.length() >= 2 && p[0] == '0' && p[1] == 'x')
                {
                    requestPrime = Integer(p.c_str());    
                }
                else
                {
                    requestPrime = Integer(("0x" + p).c_str());
                }
            }
            else
            {
                requestPrime = Integer(p.c_str());
            }
        }
        else

        // Enforces a divisible by 8 restriction, which is required by some Certificate Authorities.
        // Some places enforce divisible by 32 and 64, but I feel those requirements are too harsh.
        // I have to put my foot down somewhere.  
        if(!strcmp(args[i], "-8")) divisibleBy8 = true;
        else

        // Used to generate a prime tuple structure, which is a set of parameters that can support both encryption and signatures efficiently.
        if(!strcmp(args[i], "-tuple") || !strcmp(args[i], "-t")) tuple = atoi(args[++i]);
        else
        
        // Sets the maximum size of the offset (n). (for 2np + 1) 
        if(!strcmp(args[i], "-n") || !strcmp(args[i], "-N")) maxN = atoi(args[++i]);
        else

        // Sets the maximum size of the offset in bits (n). (for 2np + 1) 
        if(!strcmp(args[i], "-bn") || !strcmp(args[i], "-bN")) maxN = 1 << atoi(args[++i]);
        else

        // Randomize tries to randomize the generator. 
        if(!strcmp(args[i], "-r") || !strcmp(args[i], "-randomize")) randomizeGenerator = true;    
        else

        // Attempts to use the same Pohlig-Hellman Prime to find multiple Moduli. 
        if(!strcmp(args[i], "-m") || !strcmp(args[i], "-multiple")) multiple = true;    
        else

        // Sets a max number of Moduli to find from a Pohlig-Hellman prime.
        if(!strcmp(args[i], "-max")) maxModuli = atoi(args[i++ + 1]);    
        else

        // Quadratic exports a quadratic residue generator in the output file.
        if(!strcmp(args[i], "-q") || !strcmp(args[i], "-quadratic")) generatorMode = NSPDH_GENERATOR_QUADRATIC;
        else

        // Guarantees that the generator exported is the smallest (between Quadratic and Primitive Root).
        if(!strcmp(args[i], "-s") || !strcmp(args[i], "-smallest")) generatorMode = NSPDH_GENERATOR_SMALLEST;
        else

        // Attempts to verify the parameters within the given file.
        if(!strcmp(args[i], "-v") || !strcmp(args[i], "-verify") || !strcmp(args[i], "-dcv")) 
        {
            verifyDC =!strcmp(args[i], "-dcv");

            verify = args[++i];
            if(!strcmp(args[i], "-use") || !strcmp(args[i], "-u") || !strcmp(args[i], "-in")) i--;
        }
        else
        
        // Allows you to specify the output file.
        if(!strcmp(args[i], "-o") || !strcmp(args[i], "-out")) outFile = args[++i];
        else

        // Assumes it is the size parameter and gets it.
        {
            size = atoi(args[i]); 
        }    
    }

    // Storage for the parameters.
    vector<Integer> phPrimes;
    vector<Integer> modulusPrimes;
    vector<Integer> tupleBases;
    vector<int> offsets;

    // hacks for the algorithm. 
    // technically there is a potential race condition but the odds of it happening are truly astronomical.
    // so I won't use a mutex.
    volatile char completionStatus = 0;

    // Checks if divisible by 8 flag enabled and not modified.
    if(divisibleBy8 && (maxN & (1ll << 40)))
    {
        cout << "Warning: Divisible by 8 restrictions enforced. We would recommend modifying your tolerated N range for increased speed." << endl << flush;
    }

    // Checks if the multiple flag is enabled to set default max number of Moduli.    
    if(multiple)
    {
        // if the max is currently set to zero, set it to be as many moduli as possible :).
        if(!maxModuli) maxModuli = maxN;
    }
    // otherwise set it to one.
    else maxModuli = 1;

    // Ignores certain parameters if a number is passed in.
    if(requestPrime != 0)
    {
        cout << "Notice: Using a " << blog2(requestPrime) << " bit number as a source for the prime generation." << endl << flush;
        tuple = false;
    }

    // Checks if the size isn't divisible by 8 while the divisibleBy8 flag is enabled.
    // The algorithm will find compatible primes more quickly if your Pohlig-Hellman is also divisible by 8.
    if(divisibleBy8 && size % 8)
    {
        cout << "Warning: Your requested Pohlig-Hellman size is not divisible by 8. The algorithm will work more quickly for these parameters if it is. (Yes, even if you increase the size). ";
        cout << "Could we recommend size " << size + (8 - (size % 8)) << "?" << endl << flush;
    }

    // Removes the "Not Modified" flag if it currently exists.
    if(maxN & (1ll << 40))
        maxN ^= (1ll << 40);

    // If there isn't an outFile, then don't convert.
    if(outFile == nullptr) convert = false;

    // Checks if a verification was requested.
    if(verify != nullptr)
    {
        // If the verification is to be performed on an input modulus value, 
        // We'll try to compute parameters from a given modulus. 
        if (requestPrime != 0)
        {
            // Create a Pohlig variable.
            Integer pohlig = requestPrime - 1;
            int val = 1;
            
            // Factor out every possible prime.
            // (NSPs restrict which primes you're allowed to use).
            for(int i = 0; i < NSPDH_TRIAL_DIVISIONS; i++)
            { 
                while(!(pohlig % prime(i))) 
                { 
                    pohlig /= prime(i);
                    val *= prime(i);
                }
            }
            val /= 2;

            // Stores the results of the function calls.
            char p[2];

            // This is a quick hack to parallelize these two function calls.
            #pragma omp parallel for
            for(int branch = 0; branch < 2; branch++)
            {
                if(branch) p[branch] = fastPrimeC(pohlig);
                else p[branch] = fastPrimeC(requestPrime); 
            }
            
            // If they're both prime,
            if(p[0] && p[1])
            {
                // add the elements to the lists, and allow the generator to be computed.
                modulusPrimes.push_back(requestPrime);
                phPrimes.push_back(pohlig);
                offsets.push_back(val);
                tupleBases.push_back(0);
                completionStatus = NSPDH_MODULUS_FOUND;
            }
            else
            {
                // Otherwise inform the user that it isn't valid.
                cout << "This is not a valid NSP modulus." << endl;
                return 0;
            }
        }
        else 
        {
            // Used for reading in the file.
            char *buf = new char[65536];
            
            // Gets the file and its size.
            ifstream ifs(verify, ios::binary | ios::ate);
            ifstream::pos_type pos = ifs.tellg();
            
            // Reads in the entire file.
            ifs.seekg(0, ios::beg);
            ifs.read(buf, pos);
            
            // Used to return the parameters.
            Integer modulus, generator;

            // Verifies the data within the file.
            char result = verifier(buf, (int)maxN, 10, hex, verifyDC, modulus, generator);

            // Allows the person to export the parameters upon verification.
            if((result & 7) == 7 && outFile != nullptr)
            {
                // Used to tell it to flag it as a DH Parameter.
                if(convert & 2) convert |= NSPDH_DHPARAM;
                exportParameters(string(outFile), modulus, generator, convert);
            }

            delete[] buf;
            return 0;
        }
    }

    // Allows nested parallelization, which will work well since I am making the other threads sleep.
    omp_set_nested(1);
    #pragma omp parallel
    {
        cout << "t";
        bool internal = false;
        Integer primeVal, tupleBase; 
        
        
        // Searching for Prime values.
        while(completionStatus != NSPDH_MODULUS_FOUND)
        {
            // If a Prime-Tuple is requested, generate one.
            // Tuple Parameters will compute a requested bit-size factor for the Pohlig-Hellman prime.
            // This can be used for signatures (DSA-like parameters). 
            if(tuple)
            {
                // Generates a Prime "Tuple".
                tupleBase = generatePrime(tuple, &completionStatus);
                primeVal = generatePrimeTuple(size, tupleBase, &completionStatus);
                if(primeVal == 0) continue;
            }
            // If a number is passed in, it will try computing a Pohlig-Hellman prime from it.
            else if(requestPrime != 0)
            {
                long long *cache = new long long[NSPDH_TRIAL_DIVISIONS]();
                cache[0] = -1;

                // Gets the thread id. 
                int tid = omp_get_thread_num();
                
                // Starts searching for a prime related to the number passed in.
                primeVal = requestPrime + 8*1997*tid; 
                if(!(primeVal & 1)) primeVal++;
                
                while(!fastPrimeC(primeVal, cache)) 
                {
                    while(completionStatus == NSPDH_POHLIG_FOUND) Sleep(2000);
                    if(completionStatus == NSPDH_MODULUS_FOUND) break; 
                    primeVal += 2;
                }    

                delete [] cache;
            }
            else
            {
                // Generates a Prime Value.
                primeVal = generatePrime(size, &completionStatus);
            }
                   
            // Sleeps if another Pohlig was already found. (This exists here just in case two are found at the same time.)
            while(completionStatus == NSPDH_POHLIG_FOUND) Sleep(2000);
                
            // If a Modulus prime was found then break. 
            if(completionStatus == NSPDH_MODULUS_FOUND) break;

            // Tell the other threads to sleep.
            completionStatus = NSPDH_POHLIG_FOUND;

            // Output a dash to tell the user it found a Pohlig-Hellman Prime.
            cout << "-";

            // 2*p 
            Integer temp = primeVal << 1; 

            // Creates a cache to speed up the search.
            long long *cache = new long long[NSPDH_TRIAL_DIVISIONS]();
            cache[0] = -2;

            // establishes the cache.
            fastPrimeC(primeVal, cache);
            cache[0] = 0;

            // Quick hack to skip modulus computation. 
            if(maxModuli < 0)
            {
                // Add the parameters and break.
                mut.Lock();
                if(phPrimes.size() != maxModuli) 
                {
                    phPrimes.push_back(primeVal);
                    tupleBases.push_back(tupleBase);
                    modulusPrimes.push_back(0);
                    offsets.push_back(0);
                }                         
                completionStatus = NSPDH_MODULUS_FOUND;
                internal = true;
                mut.Unlock();
            }

            // Computes the n
            #pragma omp parallel for
            for(long long i = 1; i <= maxN; i++)
            { 
                unsigned long long mul = i;

                // Checks if a result has already been found/if we're supposed to be computing
                // more values
                if((int)phPrimes.size() < maxModuli)
                {

                    // Checks if divisible by 8 flag is enabled, if it is,
                    if(divisibleBy8)
                    {
                        // it attempts to hurry it up.
                        while(blog2(temp*mul + 1) % 8)
                        {
                            mul <<= 1;
                        }

                        // Checks if the current multiplier is greater than the current max N.
                        if(mul > maxN) continue;
                    }

                   
                    // is Prime(2*p*n + 1)
                    if(fastPrimeC(temp*mul + 1, cache, i))
                    {                     
                        // Tell other threads it found an NSP, and wake them up.
                        completionStatus = NSPDH_MODULUS_FOUND; 
                                    
                        // Mark that this was the thread that found it.
                        internal = true;

                        // Add the parameters and break.
                        mut.Lock();
                        if(phPrimes.size() != maxModuli) 
                        {
                            phPrimes.push_back(primeVal);
                            modulusPrimes.push_back(temp*mul + 1); 
                            tupleBases.push_back(tupleBase);
                            offsets.push_back(mul);
                        }                         
                        mut.Unlock();

                        cout << "+" << flush;
                    }
                }
            }

            delete [] cache;
            // If it didn't find an NSP within bounds, print an x and flag for randomization (it seems to find them faster with this behavior). 
            if(!internal)
            {
                cout << "x";
                
                // Wakes up the other threads.
                completionStatus = NSPDH_SEARCH;
            }
        }
    }
    
    for(int i = 0; i < phPrimes.size(); i++)
    {
        // Grab the computed parameters.
        Integer phPrime = phPrimes[i];
        Integer modulusPrime = modulusPrimes[i];
        Integer tupleBase = tupleBases[i];
        int offset = offsets[i];

        // Print out the parameters
        cout << endl << endl; 
        if(hex) cout << std::hex;
        cout << "Pohlig-Hellman Prime: " << phPrime << endl << endl;
        if(tuple) cout << "Tuple Base: " << tupleBase << endl << endl;

        if(maxModuli < 0) return 0;
        cout << "Modulus Prime: " << modulusPrime << endl << endl;
        cout << std::dec;
        cout << "Offset N: " << offset << endl; 
        
        // Print out the bit sizes.
        cout << blog2(phPrime) << " "; 
        if(tuple) cout << blog2(tupleBase) << " ";
        cout << blog2(modulusPrime) << " " << blog2(offset) << endl;

        // Find a valid primitive root.
        Integer primitiveGenerator;

        if(randomizeGenerator)
        {
            // Finds a random primitive root.
            CryptoPP::AutoSeededRandomPool asrp; 
            primitiveGenerator.Randomize(asrp, 128);    
        }
        else
        {
            // Finds the smallest possible primitive root.
            primitiveGenerator = 2; 
        }
        
        // used to find a quadratic-residue generator
        // Note: Potential optimization, when c = 2 test quadratic = 3, if that fails, quadratic is immediately 4 without a test.
        Integer quadraticGenerator(primitiveGenerator);
        

        if(generatorMode == NSPDH_GENERATOR_QUADRATIC || generatorMode == NSPDH_GENERATOR_SMALLEST)
        
        // Tries to find a quadratic generator, which will have g^(totient/2) == 1,
        while(a_exp_b_mod_c(quadraticGenerator, (modulusPrime-1)/2, modulusPrime) != 1)
        {
            quadraticGenerator++;
        }

        if(generatorMode == NSPDH_GENERATOR_PRIMITIVE_ROOT || (generatorMode == NSPDH_GENERATOR_SMALLEST && quadraticGenerator != primitiveGenerator))
        // While the value isn't a generator, increment.
        while(!checkGenerator(primitiveGenerator, modulusPrime, phPrime, offset))
        {
            primitiveGenerator++;
            if(generatorMode == NSPDH_GENERATOR_SMALLEST && primitiveGenerator >= quadraticGenerator) break; 
        } 

        // Prints out the generators.
        if(hex) cout << std::hex;

        if(generatorMode == NSPDH_GENERATOR_PRIMITIVE_ROOT || (generatorMode == NSPDH_GENERATOR_SMALLEST && quadraticGenerator != primitiveGenerator && primitiveGenerator < quadraticGenerator))
        cout << "Primitive Root Generator: " << primitiveGenerator << endl;
        else
        // if(generatorMode == NSPDH_GENERATOR_QUADRATIC || (generatorMode == NSPDH_GENERATOR_SMALLEST && quadraticGenerator <= primitiveGenerator))
        cout << "Quadratic Residue Generator: " << quadraticGenerator << endl; 
        cout << std::dec;

        // If there was a specified output file, it exports the parameters.
        if(outFile != nullptr)
        {
            // Only export this once.
            if(tuple && i == 0)
            {
                Integer g = 2;     
                Integer tot = phPrime-1;
                tot = tot/tupleBase;

                // Finds a generator of Multiplicative Order q (tupleBase).
                while(a_exp_b_mod_c(g, tot, phPrime) == 1) g++;
                g = a_exp_b_mod_c(g, tot, phPrime);
                
                // Pushes the parameters (in the correct order) to the sequence.
                vector<Integer> vec;
                vec.push_back(phPrime);
                vec.push_back(tupleBase);
                vec.push_back(g);
                
                // Specifies that this is a DSA Parameter.
                char dsaconvert = convert; 
                if(dsaconvert & 2) dsaconvert |= NSPDH_DSAPARAM;

                /*
                Integer k = 3777;
                Integer x = 234;
                Integer y = a_exp_b_mod_c(g, x, phPrime);
                Integer k1 = a_exp_b_mod_c(k, tupleBase-2, tupleBase);
                Integer h = 7113;

                Integer r = a_exp_b_mod_c(g, k, phPrime);
                r = r % tupleBase;

                Integer s = k1 * (h + r*x);
                s = s % tupleBase;

                cout << "r: " << r << endl;
                cout << "s: " << s << endl;

                Integer w = a_exp_b_mod_c(s, tupleBase-2, tupleBase);
                Integer u1 = w*h;
                u1 = u1 % tupleBase;

                Integer u2 = w*r;
                u2 = u2 % tupleBase;

                Integer v1 = a_exp_b_mod_c(g, u1, phPrime);
                Integer v2 = a_exp_b_mod_c(y, u2, phPrime);

                Integer v = (v1*v2) % phPrime;
                v = v % tupleBase;

                cout << "v: " << v << endl;
                */

                // Exports the parameters.
                exportParameters(outFile + string("_dsa"), vec, dsaconvert);
            }

            // Used for outputting "multiple" files.
            string variant = "-" + to_string(i);
            if(!multiple) variant = "";

            Integer generator(primitiveGenerator); 

            //if quadratic mode is toggled, switch the generator into a quadratic residue.
            if(generatorMode == NSPDH_GENERATOR_QUADRATIC)
            {
                generator = quadraticGenerator;
            }
            else
            // if "smallest" mode is enabled, switch the generator into the smallest between
            // the quadratic residue and the primitive root.
            if(generatorMode == NSPDH_GENERATOR_SMALLEST)
            {
                generator = min(primitiveGenerator, quadraticGenerator);
            }
            
            // Specifies that these are Diffie-Hellman Parameters.
            char dhconvert = convert; 
            if(dhconvert & 2) dhconvert |= NSPDH_DHPARAM;

            // Exports the parameters.
            exportParameters(string(outFile) + variant, modulusPrime, generator, dhconvert);
           
        } 
    }
    return 0;
}
