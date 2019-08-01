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
     Or to be precise, it should be **difficult to find two messages M1 and M2 such that H(M1) = H(M2)**
     
  4. Should posses **avalanche-effect | aka diffusion in cryptographic parlance**  
     Which means **even a small change in the input** message should **result in a drastically different hash value**.
  
  5. Should be **computationally fast** to compute the hash.
  
 ## Let's rollup our sleeves and generate some *hashes (message digests)* using Java Security API.
 
 The following are the valid *Message Digest Algorithm Names* supported by the Java Security API to perform one-way hashing:
 
  | Algorithm Names |
  |---|
  | MD2 |
  | MD5 |  
  | SHA-1 |
  | SHA-224 |
  | SHA-256 |
  | SHA-384 |
  | SHA-512 |

  [Reference of the above can be found here](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest).
  
  ```java
package com.experiments;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashGenerator {

   public static String
          createDigest(String inputMessage,
                       String messageDigestAlgorithm) throws NoSuchAlgorithmException {
      MessageDigest digester = MessageDigest.getInstance(messageDigestAlgorithm);
      byte[] digestAsByteArray =
                               digester.digest(inputMessage.getBytes(StandardCharsets.UTF_8));
      return bytesToHex(digestAsByteArray);
   }

   private static String bytesToHex(byte[] bytes) {
      StringBuilder builder = new StringBuilder();
      for (byte each : bytes) {
         builder.append(String.format("%02x", each));
      }
      return builder.toString();
   }

   public static void main(String[] args) throws Exception {
      String inputMessage = "Welcome to the world of Cryptography!";
      
      String md5Algo = "MD5";
      String md5Hash = createDigest(inputMessage, md5Algo);
      System.out.println(String.format("%-10s : %-120s", md5Algo, md5Hash));
      
      String sha256Algo = "SHA-256";
      String sha256Hash = createDigest(inputMessage, sha256Algo);
      System.out.println(String.format("%-10s : %-120s", sha256Algo, sha256Hash));
      
      String sha512Algo = "SHA-512";
      String sha512Hash = createDigest(inputMessage, sha512Algo);
      System.out.println(String.format("%-10s : %-120s", sha512Algo, sha512Hash));
   }
}
```
**Output**  
>`MD5        : fafea129696d518803971f70561ef831`                                                                                     
>`SHA-256    : 3a9af738f328bfafcedfd3d1ee15c412ce4d4a21e5fff5d9f3074fe900efde1a`                                                       
>`SHA-512    : 8bbc672e5c2a28dc5bc56ccc5f0e4a3b330c60d6e54e943e00c14aab4ecf3602bae785e3c88111f08350f7934e14cac447b1f922a5aba6cf4e6f924fff2ebd60`

## Safeguarding from attacks like Bruteforce, Dictionary Attacks and Rainbow Tables:

 1. Guessing the correct password (in plaintext) using the **bruteforce-attack**:
 
    The bruteforce-attack is trying all the possible combinations of alphanumeric and special characters for various password lengths.
    
    For example, It's like trying all the numbers between 000 to 999 for a 3 digit number lock in a briefcase.
 
 2. Guessing the correct password (in plaintext) using the **dictionary-attack**:
 
    The dictionary-attack is a refinement or trying a sub set of the password combinations which are very popular and those that are         derived from the user's family names, birthdates, place of origin and the like.
 
    Since the passwords to be tried are a handful compared to the bruteforce, there is a very good chance that the hacker may not guess     the correct password too.
    
    
    ### Avoiding Bruteforce / Dictionary Attacks
    
    - **Lock the accounts temporarily** (Don't engage in authentication at all for the next 3 hours or 24 hours) after 3 or 5                  consecutive authentication failures. This would effectively make the automated hacking routines from keep on trying all the              password combinations.
    
    - **Using bigger password lengths** would increase the time taken to try all the combinations. For example, a 8 digit password (any        combination of case insensitive alphanumeric, punctuations and special character allowed) would have **95<sup>8</sup>** possible        password combinations.
    
  3. Getting (Reverse Engineer) the password from the *hash* of it using **Rainbow Table attacks**:

     Rainbow Tables are one of the precomputation attacks that employ hash chaining which facilitates less storage compared to the            Dictionary attack.
    
     
## Adding **Salt** to the rescue:   

  Rainbow table attacks could be thwarted by adding a large sized **salt** to the password while hashing.
  
  Passwords could be salted and the hashes are generated as follows:
  
```
    saltedhash(password) = hash(password + salt)

    Or

    saltedhash(password) = hash(hash(password) + salt)
```

> **Salt adds more entropy to the password. i.e., the randomness of the password to be hashed would be drammatically increased.** **NIST** National Institute of Standards and Technology recommends the salt length be atleast **128 bits**.

## Let's add some **salt** while generating classic hashes (MD5 and SHA) using Java

```java

import java.security.SecureRandom;

public class HashGenerator {

  ...
  ...
  
   public static String
          createSaltedDigest1(String inputMessage,
                              String salt,
                              String messageDigestAlgorithm) throws NoSuchAlgorithmException {
      return createDigest(inputMessage + salt, messageDigestAlgorithm);
   }

   public static String
          createSaltedDigest2(String inputMessage,
                              String salt,
                              String messageDigestAlgorithm) throws NoSuchAlgorithmException {
      String intermediateDigest = createDigest(inputMessage, messageDigestAlgorithm);
      return createDigest(intermediateDigest + salt, messageDigestAlgorithm);
   }

   public static String
          createRandomSaltedDigest(String inputMessage,
                                   String messageDigestAlgorithm) throws NoSuchAlgorithmException {
      byte[] randomSalt = new byte[32];
      SecureRandom random = new SecureRandom();
      random.nextBytes(randomSalt);
      return createSaltedDigest1(inputMessage, new String(randomSalt), messageDigestAlgorithm);
   }

   public static void main(String[] args) throws Exception {
   
      ...
      ...
      
      String inputMessage = "Welcome to the world of Cryptography!";
      String md5Algo = "MD5";
      String md5SaltedHash1 = createSaltedDigest1(inputMessage,
                                                  "salty-cracker-jacker-@#$-965",
                                                  md5Algo);
      System.out.println(String
         .format("User Specified Salt, V1  : %-10s : %-120s", md5Algo, md5SaltedHash1));
      String md5SaltedHash2 = createSaltedDigest2(inputMessage,
                                                  "salty-cracker-jacker-@#$-965",
                                                  md5Algo);
      System.out.println(String
         .format("User Specified Salt, V2  : %-10s : %-120s", md5Algo, md5SaltedHash2));
      String md5RandomSaltedHash = createRandomSaltedDigest(inputMessage, md5Algo);
      System.out.println(String
         .format("Secure Random Salt (PRNG): %-10s : %-120s", md5Algo, md5RandomSaltedHash));
   }

   
```

### Ouput

```
User Specified Salt, V1  : MD5        : c72ca42b6ebf256d269b3ea44bf4cc1a

User Specified Salt, V2  : MD5        : e68352f48100a21f9cbbe05303556c84

Secure Random Salt (PRNG): MD5        : bc7f152292fa1240e5a22cfad2352a00                                                                 
```

## Ashley Madison Data Breach in 2011 and MD5 hashed passwords!!!

As per wikipedia, a data breach at Ashley Madison looses over 36 million password hashes to a hacking team.
Out of those 36 million, over 11 million passwords are **MD5** hashed **(probably without a salt)** and are easily hacked back to original passwords.
An interesting note is that the rest of the passwords are **Bcrypt** hashed which are **inherently salted**.

**So, Be Wise in choosing the Hashing Algorithm!.**

[Ashley Madison Breach](https://en.wikipedia.org/wiki/Ashley_Madison_data_breach)

## LinkedIn 2012 Data breach!!!

As per wiki, Over 6.5 million emails/passwords that are SHA-1 hashed **with NO SALT** have been hacked.

[LinkedIn Breach](https://en.wikipedia.org/wiki/2012_LinkedIn_hack)

## BCrypt using jBCrypt Java Library

Maven coordinates for the jBCrypt Library:

```xml
<dependency>
  <groupId>org.mindrot</groupId>
  <artifactId>jbcrypt</artifactId>
  <version>0.4</version>
</dependency>
```

```java
package com.experiments;

import org.mindrot.jbcrypt.BCrypt;

public class BcryptHashGenerator {

   public static String createDigest(String inputMessage) {
      return BCrypt.hashpw(inputMessage, BCrypt.gensalt(12));
   }

   public static boolean verifyDigest(String inputMessage, String digest) {
      return BCrypt.checkpw(inputMessage, digest);
   }

   public static void main(String[] args) {
      String inputMessage = "WelKome to Amsterdam, Comrade!";
      String wrongInputMessage = "somedummypassphrase";
      
      String bcryptedHash = createDigest(inputMessage);
      
      System.out.println("Bcrypted Hash : " + bcryptedHash);
      System.out.println(inputMessage + " : " + verifyDigest(inputMessage, bcryptedHash));
      System.out.println(wrongInputMessage + " : " + verifyDigest(wrongInputMessage, bcryptedHash));
   }
}
```

### Ouput
```
Bcrypted Hash : $2a$12$3sqD.FY8GPN3F1J2uhVnMOXuB4X3yfZ9uQ0DKAKWOiqLKgtV/LS0W   
WelKome to Amsterdam, Comrade! : true   
somedummypassphrase : false  
```

## PBKDF2 based hashing which comes along with JDK

```java
package com.experiments;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2HashGenerator {

   public static String createPBKDF2Digest(String inputMessage,
                                           String randomSalt) throws InvalidKeySpecException,
                                                              NoSuchAlgorithmException {
      PBEKeySpec keySpec = new PBEKeySpec(inputMessage.toCharArray(),
                                          randomSalt.getBytes(),
                                          1000,
                                          256);
      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      byte[] encoded = keyFactory.generateSecret(keySpec).getEncoded();
      return bytesToHex(encoded);
   }

   private static String generateRandomSalt() throws NoSuchAlgorithmException {
      // Let's use SHA1 Pseudo Random Number Generator.
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      byte[] salt = new byte[64];
      random.nextBytes(salt);
      return new String(salt);
   }

   private static String bytesToHex(byte[] bytes) {
      StringBuilder builder = new StringBuilder();
      for (byte each : bytes) {
         builder.append(String.format("%02x", each));
      }
      return builder.toString();
   }

   public static void main(String[] args) throws Exception {
      String inputMessage = "Hola Hashing from el camino real!!!";
      String randomSalt = generateRandomSalt();
      String pbkdf2Digest = createPBKDF2Digest(inputMessage, randomSalt);
      System.out.println("Random Salt : " + bytesToHex(randomSalt.getBytes()));
      System.out.println("PBKDF2 Digest : " + pbkdf2Digest);
   }
}

```

### Output

```
Random Salt : efbfbdd49010efbfbdefbfbdefbfbd2b6d7eefbfbd674e09efbfbd2fefbfbd45efbfbd0449efbfbdefbfbd3d0fefbfbd072419efbfbdefbfbdefbfbdefbfbdefbfbdefbfbd0eefbfbd01d390d2a87befbfbd1f09efbfbdefbfbd62efbfbd25efbfbd7f627268efbfbd28efbfbd20efbfbdefbfbd5869   
PBKDF2 Digest : 64819bed0aee4367b89627dc95c4ec00a218035a2e550d30b384b04c44dead78

```
____  

## References

 0. [One Way Hashing!](https://www.cs.rit.edu/~ark/lectures/onewayhash/onewayhash.shtml)
 1. [Storing Salts!](https://security.stackexchange.com/questions/17421/how-to-store-salt)
 2. [Bytes to Hexadecimal conversion!](https://www.mkyong.com/java/java-how-to-convert-bytes-to-hex/)
 3. [How many password combinations!](https://math.stackexchange.com/questions/739874/how-many-possible-combinations-in-8-character-password)
 4. [Ahsley Madison breach and a nice writeup on password hashing!](https://www.acunetix.com/blog/articles/password-hashing-and-the-ashley-madison-hack/)
 5. [Various ways to convert Hex to Bytes and vice versa by Baeldung!](https://en.wikipedia.org/wiki/2012_LinkedIn_hack)
 6. [PBKDFv2!](https://howtodoinjava.com/security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/)
