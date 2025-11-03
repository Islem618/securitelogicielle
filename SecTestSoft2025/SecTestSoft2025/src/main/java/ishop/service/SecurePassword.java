package ishop.service;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;


import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class SecurePassword {

	public static final int ITERATIONS = 1024;
	
	public static String generateStrongPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        char[] chars = password.toCharArray();
        
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        
       
        PBEKeySpec spec = new PBEKeySpec(chars, salt, ITERATIONS, 512);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return toHex(salt) + ":" + toHex(hash);
    }
	
      
    private static String toHex(byte[] array) throws NoSuchAlgorithmException
    {
        BigInteger bi = new BigInteger(1, array);
        String hex = bi.toString(16);
        int paddingLength = (array.length * 2) - hex.length();
        if(paddingLength > 0)
        {
            return String.format("%0"  +paddingLength + "d", 0) + hex;
        }else{
            return hex;
        }
    }
    
    public static boolean validatePassword(String originalPassword, String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        String slt = storedPassword.split(":")[1];
        String pswd = storedPassword.split(":")[0];
    	byte[] salt = fromHex(slt);
        byte[] hash = fromHex(pswd);
         
        PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, ITERATIONS, hash.length * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] testHash = skf.generateSecret(spec).getEncoded();
         
        int diff = hash.length ^ testHash.length;
        for(int i = 0; i < hash.length && i < testHash.length; i++)
        {
            diff |= hash[i] ^ testHash[i];
        }
        return diff == 0;
    }
    private static byte[] fromHex(String hex) throws NoSuchAlgorithmException
    {
        byte[] bytes = new byte[hex.length() / 2];
        for(int i = 0; i<bytes.length ;i++)
        {
            bytes[i] = (byte)Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return bytes;
    }

}
