package org.example;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
public class Message {
    SecretKey key;
    Cipher cipher;
    String message;
    String id;
    boolean encrypted;
    static int count;
    public Message(String msg) {
        message = msg;
        encrypted = false;

        count++;
        id = String.valueOf(count);
    }

    public String encryptMessage() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        if(encrypted){
            return "String is already encrypted!";
        }
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        key = generator.generateKey();

        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        message = Base64.getEncoder().encodeToString(encryptedBytes);
        encrypted = true;
        return message;
    }

    public String decryptMessage() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        if(!encrypted){
            return "String is already decrypted!";
        }

        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        message = new String(decryptedBytes);
        encrypted = false;
        return message;
    }

    public String getMessage() {
        return message;
    }

    public String getId() {
        return id;
    }

}
