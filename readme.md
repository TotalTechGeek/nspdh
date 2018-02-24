# nspdh 

### So, what is it?
nspdh generates secure parameters for Discrete Log Cryptography, like the Diffie-Hellman key exchange and the Digital Signature Algorithm, and does it much (potentially hundreds to thousands of times) faster than our top standard algorithms. 

The algorithm can even generate prime "tuple" parameters that can be used for complete public key cryptography (with both encryption and signatures). 

## Faster?

It's reasonably fast, and I think with speed improvements like this Discrete Log Cryptography might finally be seen as a viable alternative to RSA again. The speed boost over the standard algorithms increases with the bit size requested.

On a 2.4GHz i3-3110M Processor, it was able to generate 2048 bit parameters at an average of 8 seconds.
OpenSSL consistently lagged behind, with each sample taking closer to two minutes. 

At 3072 bits, nspdh was able to generate new parameters nearly every 20 seconds.
OpenSSL took nearly four minutes.

At 8192 bits, nspdh was able to generate parameters consistently in between 7 and 20 minutes.
I left OpenSSL running for nearly 5 days before I had to terminate the process. 

Due to a lack of computing power, I don't have a large sample size on larger parameters, but it found 16384 bit parameters in 4 hours. 

## Okay, what's the catch? 
### a.k.a. what are you doing differently? 

You're correct to be suspicious! How would some unknown amateur be able to design something like this "first"? 

Well... I went against standard practices... but with good reason! 

**Before clicking off, don't worry, I didn't make the amateur mistake of just selecting a random prime.**

After thoroughly researching Discrete Log Cryptography and contacting a few people who have written on the topic, I disagreed with a few "design" and measurement decisions early cryptographers made a few decades ago. Let me give provide background:

The Discrete Logarithm problem has quite a few attacks, while the well known attacks focus mostly on the prime modulus, there are attacks that rely solely upon the largest factor of the prime modulus - 1. The specific algorithm is called the [Pohlig-Hellman algorithm](https://en.wikipedia.org/wiki/Pohlig%E2%80%93Hellman_algorithm).

Since the general consensus was that you should measure the strength of a cyclic group by the size of the modulus, early cryptographers made the decision to try to "maximize" the strength of the modulus against this algorithm for any given modulus. This led to them using "Safe-Primes", which exist in the form 2p+1, where p is a random prime. 

This effectively guarantees that the largest factor will be as close as it possibly can be at any given bit size (just one bit off).  

Clever thinking, right? . . .  

Well, kinda. Maybe. *Not really...* 

They're actually looking at the problem **backwards**, but we'll be getting to that. This was a really good idea when Diffie-Hellman keys were 256 and 512 bits, when a larger gap dramatically impacted the security. Those kinds of primes are also much denser in those ranges. But as we're finding that these primes are quite sparse at larger sizes, maybe it's time to consider that this isn't the best approach after all.

You see, the size of the largest factor of the modulus prime-1 is in a sense the lower bound of the cyclic group's security, since it will always be smaller than the modulus prime itself. The standard ideology uses a bit of a top-down approach, where it focuses all the attention solely the upper-bound and sets harsh restrictions for everything below it. 

It's backwards, and once you reverse your thinking, an alternative approach becomes obvious. 

## Bottom-Up Discrete Log Parameter Generation.

Because the terminology doesn't seem to exist, since we've placed our attention entirely on the modulus, I will propose some to make this description simpler.

I will be calling the largest factor of the modulus prime-1 the "Pohlig-Hellman prime", its size the "Pohlig-Hellman strength", and the modulus size "modulus strength".

My method is this: 
- Generate a Pohlig-Hellman Prime at the requested strength.
- Find a corresponding prime modulus within a bounded range. 

The prime modulus will exist in the form 2np + 1, where n is a random integer within a bounded range. Why bound this range? To make it simple and fast to verify! This is called a "nearly safe prime", but no less secure than a "safe prime".

n by default is 4096, but 65536 is still acceptable (it's actually easy to verify all n values up to 2^32, but I don't recommend going above 2^24).  

Primes within this form are far less sparse (because all primes greater than 3 exist in this form), and are far easier to find. While this creates a Discrete Log Group with a greater gap between the Pohlig-Hellman Prime and the Modulus Prime, that will have **zero** known effect on its cryptographic strength. No known Discrete Log Algorithm depends on the gap between the primes. 

As an example, a cyclic group with a 2048 Bit Pohlig-Hellman Strength might have a 2056 Bit Modulus Strength, both of which are technically better than the previous 2047/2048 combination. 

And also! In the time it used to take to generate 2048 bit parameters, you can have far more secure 5120 bit parameters.

#### But... I don't like the gap.

[Where have I heard this before?](https://youtu.be/pdR7WW3XR9c?t=52)

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

Which will run the init script and fetch all necessary dependencies (Boost, ASN1C) and will patch the files to be built for your OS. Building with dave will allow you to support OpenSSL files. 

Java 8 or higher is required. Tested with g++, clang (aliased as g++), and Mingw32_64.

### Building without dave

If you do not want to build with dave, or you would prefer to build the software with a different compiler, you will need to download and extract Boost, and include it in your build. The software also requires the OpenMP flag to be enabled for your compiler. 

This build will not include the OpenSSL compatibility features.

You will basically do something along the lines of
```
cl src/*.cpp /fopenmp /Ox
```
