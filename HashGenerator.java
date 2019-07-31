package com.experiments;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class HashGenerator {

   public static String
          createDigest(String inputMessage,
                       String messageDigestAlgorithm) throws NoSuchAlgorithmException {
      MessageDigest digester = MessageDigest.getInstance(messageDigestAlgorithm);
      byte[] digestAsByteArray =
                               digester.digest(inputMessage.getBytes(StandardCharsets.UTF_8));
      return bytesToHex(digestAsByteArray);
   }

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
}
