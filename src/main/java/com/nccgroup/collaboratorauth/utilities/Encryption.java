package com.nccgroup.collaboratorauth.utilities;


import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class Encryption {

    private static SecretKey generateKey(String secret) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(secret.toCharArray(), "CollaboratorAuth".getBytes(), 128, 256);
        SecretKey tmpSecret = keyFactory.generateSecret(keySpec);

        return new SecretKeySpec(tmpSecret.getEncoded(), "AES");
    }


    public static byte[] aesEncryptRequest(String secret, String request) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidParameterSpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKey secretKey = generateKey(secret);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] cipherText = cipher.doFinal(request.getBytes());

        byte[] cipherTextWithIv = new byte[cipherText.length+iv.length];
        System.arraycopy(iv, 0, cipherTextWithIv, 0, iv.length);
        System.arraycopy(cipherText, 0, cipherTextWithIv, iv.length, cipherText.length);
        return cipherTextWithIv;
    }


    public static String aesDecryptRequest(String secret, byte[] encryptedWithIv) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKey secretKey = generateKey(secret);
        byte[] iv = Arrays.copyOfRange(encryptedWithIv, 0, 16);
        byte[] cipherText = Arrays.copyOfRange(encryptedWithIv, 16, encryptedWithIv.length);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        String plaintext = new String(cipher.doFinal(cipherText));

        return plaintext;
    }
}
