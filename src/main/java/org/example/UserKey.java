package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class UserKey {
    private String user;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    /**
     * Constructor for UserKey to link a user's discord ID to a keypair.
     *
     * @param user The discord ID of the user
     * @param privateKey The private key of the user
     * @param publicKey The public key of the user
     */
    public UserKey(String user, PrivateKey privateKey, PublicKey publicKey){
        this.user = user;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Get the discord ID of the UserKey.
     *
     * @return The discord ID of the UserKey
     */
    public String getUser(){
        return user;
    }

    /**
     * Get the public key of the UserKey.
     *
     * @return The public key of the UserKey
     */
    public String getPublicKey(){
        return new String(Base64.getEncoder().encode(publicKey.getEncoded()));
    }

    /**
     * Set the public key of the UserKey.
     *
     * @param publicKey The public key to set the UserKey to
     */
    public void setPublicKey(PublicKey publicKey){
        this.publicKey = publicKey;
    }

    /**
     * Set the private key of the UserKey.
     *
     * @param privateKey The private key to set the UserKey to
     */
    public void setPrivateKey(PrivateKey privateKey){
        this.privateKey = privateKey;
    }

    /**
     * Encrypt a message using asymmetric encryption with the UserKey's public key.
     *
     * @param message The message to encrypt
     * @return The ciphertext
     */
    public String encryptMessageAsymmetric(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Encrypt a message using asymmetric encryption with a specified public key.
     *
     * @param pubKey The public key to use
     * @param message The message to encrypt
     * @return The ciphertext
     */
    public static String encryptMessageAsymmetric(PublicKey pubKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypt a message using asymmetric encryption with a UserKey's private key.
     *
     * @param message The ciphertext to decrypt
     * @return The plaintext
     */
    public String decryptMessageAsymmetric(String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    /**
     * Decrypt a message using asymmetric encryption with a specified private key.
     *
     * @param privKey The private key to use
     * @param message The ciphertext to decrypt
     * @return The plaintext
     */
    public static String decryptMessageAsymmetric(PrivateKey privKey, String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }
}
