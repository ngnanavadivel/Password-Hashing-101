# Hashing
A quick walk through of generating hashes using popular hash functions like MD5, SHA1, SHA256, SHA512, PBKDF2 and the like.

## What is a Hash function?

  - A mathematical algorithm that transforms an *arbitrary sized data* into a *smaller fixed length data*.
  - The result of the hashing functions is often called by various names like **Hash, Digest, checksum, fingerprint** etc.,

## Characteristics of a good Hashing function:

  1. Should be **deterministic**.   
     Which means the hashing function should always return the **SAME hash** value for a given message consistently.
  2. Should be **one-way**.  
     Which means it should be practically infeasible to reverse engineer the hash value back to the original message.
  3. Should be **collision-resistant**
     Which means it should be infeasible to generate the **SAME hash** from two different messages.
  4. Should posses **avalanche-effect**
     Which means even a small change in the input message should result in a drastically different hash value.
  
