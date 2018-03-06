# nspdh 

### So, what is it?
nspdh generates secure parameters for Discrete Log Cryptography, like the Diffie-Hellman key exchange and the Digital Signature Algorithm, and does it much (potentially hundreds to thousands of times) faster than our top standard algorithms. 

## Faster?

It's reasonably fast, and I think with speed improvements like this Discrete Log Cryptography might finally be seen as a viable alternative to RSA again. The speed boost over the standard algorithms increases with the bit size requested.

On a 2.4GHz i3-3110M Processor (from 2012), it was able to generate 2048 bit parameters at an average of 4 seconds.
OpenSSL consistently lagged behind, with each sample taking closer to two minutes. 

At 3072 bits, nspdh was able to generate new parameters nearly every 7.7 seconds.
OpenSSL took nearly four minutes.

At 4096 bits, nspdh was able to generate new parameters nearly every 14 seconds.

At 8192 bits, nspdh was able to generate parameters consistently in the range of 2-3 minutes.
I left OpenSSL running for nearly 5 days before I had to terminate the process. 

16384 bit parameters can be found in 6-18 minutes. 

## What's being done differently? 

Well... it goes against the current standard practices *(for Diffie-Hellman Parameters)*... but with good reason! 

**Don't worry: I didn't make the amateur mistake of just selecting a random prime.**

After researching Discrete Log Cryptography and contacting a few people who have written on the topic, I disagreed with a few "design" and measurement decisions earlier cryptographers made a few decades ago. 

The Discrete Logarithm problem has quite a few attack algorithms, while most of the well known attacks focus mostly on the modulus, there are attacks that rely solely upon the largest prime factor of the modulus - 1. The specific algorithm is called the [Pohlig-Hellman algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm).

Since at the time the general consensus was that you should measure the strength of a cyclic group by the size of the modulus, cryptographers made the decision to attempt to "maximize" the strength of the cyclic group against this attack for any given modulus. This led to them using "Safe-Primes", which exist in the form 2p+1, where p is a prime. 

This effectively guarantees that the largest prime factor will be at a minimal distance from the modulus, "maximizing" the cyclic group's strength.  

The problem is that the problem was being observed **backwards**. This decision was decent when Diffie-Hellman moduli were 256 and 384 bits, when a slightly larger gap could dramatically impact the security. However, safe primes are also far more dense in those ranges. Safe primes are quite sparse at larger sizes, so it might be time to consider another approach.

The size of the largest factor of the modulus-1 is the lower bound of the cyclic group's security, since it will always be smaller than the modulus prime itself. The standard ideology currently uses a bit of a top-down approach, that generates a modulus with a minimal distance from the factor. 

This approach is backwards, and once you reverse your thinking, an alternative approach becomes obvious. 

## Bottom-Up Discrete Log Parameter Generation.

Because the terminology doesn't seem to exist, I will propose some to make this description simpler.

I will be calling the largest prime factor of the modulus - 1 the "Pohlig-Hellman prime", its log size the "Pohlig-Hellman strength", and the modulus log size "modulus strength".

The method is this: 
- Generate a Pohlig-Hellman Prime at the requested strength.
- Find a corresponding prime modulus within a bounded range. 

The prime modulus will exist in the form 2np + 1, where n is a random integer within a bounded range. This range is bounded to make the parameters easy to verify against backdoors (since you can easily find the pohlig value from the modulus). This is called a "nearly safe prime", but is no less secure than a "safe prime".

n by default is 4096, but 65536 is still acceptable (it's actually easy to verify all n values up to 2^32, but I don't recommend going above 2^24).  

Primes within this form are far less sparse (technically all primes greater than 3 exist in this form), and are far easier to find. While this creates a Discrete Log Group with a slightly larger gap between the PH Prime and the Modulus, this will have **zero** impact on its cryptographic strength. No known algorithm can exploit the gap between the primes (otherwise DSA would be broken). 

As an example, a cyclic group with a 2048 Bit Pohlig-Hellman Strength might have a 2056 Bit Modulus Strength. (2048, 2056) is provably better than the (2047, 2048) combination, against all known algorithms. 

In the time it used to take to generate 2048 bit parameters, you could generate far more secure 5120 bit parameters.

---

**Let me to be clear:** This is not a *completely* new approach, or necessarily a new mathematical realization. The NIST already acknowledges this is secure in [their DSA specifications](https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf) in the choice of their (L, N) pairs. I'm just recommending a different scheme that'll accelerate parameter generation and still allow verification against backdoors (without extra file overhead).
  
I do, however, have some concerns with the current DSA specifications. If the initial steps of the Pohlig-Hellman algorithm could be computed on a quantum computer, and the DSA cyclic group was "backdoored" (intentionally constructed in such a way that the greatest factor will be N), then a Quantum computer of size N might be able to break the cyclic group quickly (rather than size L).  

## How do I actually use the software?

At the moment, I want to focus on publishing a math paper to prove the security of Nearly Safe Primes to skeptics, so I haven't fleshed out the documentation yet.

Until then, try running it with:
```
nspdh -h
```

## To Build 
### Building with dave 

To build the software, run 

``` 
java -jar Dave.jar 
```

Which will run the init script and fetch all necessary dependencies (Crypto++, ASN1C) and will patch the files to be built for your OS. Building with dave will allow you to support OpenSSL files. 

Java 8 or higher is required. Tested with g++, clang (aliased as g++), and Mingw32_64.

**WARNING**: If you are compiling this project for the Mac, the default clang compiler will not work, as it lacks OpenMP support. If you wish to compile this project, you may have to it to a different compiler using something along the lines of: 
```
export CXX=g++-7
export CCX=gcc-7
```
Prior to running dave.

Support for Visual Studio is being considered.

### Building without dave

If you do not want to build with dave, or you would prefer to build the software with a different compiler, you will need to download and extract Crypto++, build it, and include it in the final build. The software also requires the OpenMP flag to be enabled for your compiler. 

This build will not include the OpenSSL compatibility features.

For example, for the Visual Studio compiler you will basically do something along the lines of
```
cl src/*.cpp /openmp /Ox cryptlib.lib /DForce2011
```
