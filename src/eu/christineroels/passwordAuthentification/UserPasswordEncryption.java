package eu.christineroels.passwordAuthentification;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;


/** We don't want to store user passwords as plain text.
 * So we provide a class to scramble the passwords
 * In each examples, we use cryptographic hash functions, with two of its
 * algorithms: SHA-1 and PBKDF2WithHmacSHA1.
 * It is a one-way repeatable process to avoid reverse-engineering
 * the password from the hash.
 */
public class UserPasswordEncryption {
    private final String plainPassword;

    public UserPasswordEncryption(String plainPassword)  {

        this.plainPassword = plainPassword;
    }

    //Simple, natively supported by Java but less recommended approach (SHA-versionNumber)
    public byte[] hashUserPassword(String algorithm) throws NoSuchAlgorithmException{
        //MesssageDigest is a cryptographic service, it is not thread-safe
        //We have to create an instance for each thread
        //getInstance() request this service from any of the available security provider
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(this.plainPassword.getBytes());
    }
    //Recommended, natively supported by Java approach as it is a slower process
    // has a configurable strength (related to the slowness of the algorithm)
    //and a random sequence unique to each new hash
    public byte[] getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        //This line of code fills the array with random bytes
        random.nextBytes(salt);
        //We will inject these random bytes in the hash code to reinforce its entropy
        return salt;
    }
    public byte[] PBKDF2userPassword(byte[] salt, String plainPassword, String algorithm, int strength, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Where strength is how many iteration we set to slow down the process
        // (to avoid brute force attacks)
        KeySpec specification = new PBEKeySpec(plainPassword.toCharArray(),salt,strength,keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
        return factory.generateSecret(specification).getEncoded();
    }
    public byte[] PBKDF2userPassword(String plainPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Where strength is how many iteration we set to slow down the process
        // (to avoid brute force attacks)
        KeySpec specification = new PBEKeySpec(plainPassword.toCharArray(), getSalt(),65536,128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return factory.generateSecret(specification).getEncoded();
    }
    public byte[] PBKDF2userPassword(byte[] salt,String plainPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        //Where strength is how many iteration we set to slow down the process
        // (to avoid brute force attacks)
        KeySpec specification = new PBEKeySpec(plainPassword.toCharArray(), salt,65536,128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return factory.generateSecret(specification).getEncoded();
    }
    //To store an hexadecimal representation in the database (traditionally more understandable by developers,
    //easy to see how many bytes it contains (by converting to 1 and 0 on a piece of paper))
    public String bytesToHexadecimal(byte[] hash){
        StringBuilder hexString = new StringBuilder(2*hash.length);
        for(int i = 0; i<hash.length; i++){
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length()==1){
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    //Additional recommended algorithms supported by Spring Security
    //BCrypt, SCrypt

    //PasswordEncoder Interface implementations
    //strength configuration available
    //salt is generate internally
    //The algorithm stores the salt within the output hash for later use in validating a password


    public static void main(String[] args) {
        UserPasswordEncryption userPasswordEncryption = new UserPasswordEncryption("rock");
        try {
            //It is deterministic (always produces the same hash)
            //It is not reversible
            byte[] hashedPassword = userPasswordEncryption.hashUserPassword("SHA-1");
            System.out.println("Hashed value: " + hashedPassword);
            System.out.println("Hexadecimal equivalent: "+ userPasswordEncryption.bytesToHexadecimal(hashedPassword));
            hashedPassword = userPasswordEncryption.hashUserPassword("SHA-512");
            System.out.println("Longer = 512 bits: "+hashedPassword);
            //It has high entropy (it produces a vastly different hash)
            //It resists collisions (unique hash for each message)
            userPasswordEncryption = new UserPasswordEncryption("rick");
            System.out.println("I only change one letter in my plain word and " +
                    "the hash becomes "+ userPasswordEncryption.hashUserPassword("SHA-1"));

        }catch (NoSuchAlgorithmException nsae){
            System.out.println("Not a valid algorithm");
        }
        try{
            byte[] hash = userPasswordEncryption.PBKDF2userPassword(userPasswordEncryption.getSalt(), userPasswordEncryption.plainPassword,
                    "PBKDF2WithHmacSHA1",65536,128);
            System.out.println("Hash value with PBKDF2 algorithm: " + hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            System.out.println("It is an unknown algorithm or an invalid key specification");
            e.printStackTrace();
        }
    }
}
