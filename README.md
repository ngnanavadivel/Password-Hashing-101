# Hashing
A quick journey into the world of cryptographic hash functions and an attempt to generate hashes using popular hash functions like MD5, SHA1, SHA2 (224, 256, 384, 512), SHA3, PBKDF2, bcrypt, scrypt and the like.

## What is a Hash function?

  - A mathematical algorithm that transforms an **arbitrary sized input message** into a **smaller fixed length hash**.
  - The result of the hashing functions is often called by various names like **Hash, Digest, checksum, fingerprint** etc.,

## Characteristics of a good Hashing function:

  1. Should be **deterministic**.   
     Which means the hashing function **should always return the SAME hash** value for a given message consistently.
     
  2. Should be **one-way | preimage resistant**.  
     Which means it should be computationally **infeasible to reverse engineer** the hash value back to the original message.
     
  3. Should be **strongly collision free | second-preimage-resistant**  
     Which means it should be **infeasible to generate the SAME hash** from two different messages.
     Or to be precise, it should be **difficult to find two messages M1 and M2 such that H(M1) = H(M2)
     
  4. Should posses **avalanche-effect | aka diffusion in cryptographic parlance**  
     Which means **even a small change in the input** message should **result in a drastically different hash value**.
  
  5. Should be **computationally fast** to compute the hash.
  
 ## Let's rollup our sleeves and generate some *hashes (message digests)* using Java Security API.
 
 The following are the valid Message Digest Algorithm names supported by the Java Security API to perform one-way hashing:
 
  | Algorithm Names |
  |---|
  | MD2 |
  | MD5 |  
  | SHA-1 |
  | SHA-224 |
  | SHA-256 |
  | SHA-384 |
  | SHA-512 |

