package org.example;

import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.hooks.ListenerAdapter;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Commands extends ListenerAdapter {

    @Override
    public void onSlashCommandInteraction(SlashCommandInteractionEvent e) {
        switch (e.getName()) {
            case "hi":
                e.reply("hi").queue();
                break;
            case "convert":
                String type1 = e.getOption("type1").getAsString();
                String type2 = e.getOption("type2").getAsString();
                String data = e.getOption("data").getAsString();

                if (type1.equalsIgnoreCase("bits")) {
                    e.reply(convertBits(type2.toLowerCase(), data)).queue();
                } else if (type1.equalsIgnoreCase("string")) {
                    e.reply(convertString(type2.toLowerCase(), data)).queue();
                } else if (type1.equalsIgnoreCase("hex")) {
                    e.reply(convertHex(type2.toLowerCase(), data)).queue();
                } else if (type1.equalsIgnoreCase("base64")) {
                    e.reply(convertBase64(type2.toLowerCase(), data)).queue();
                } else {
                    e.reply("Incorrect value: \"" + type1 + "\" does not match Bits, String, Hex, or Base64.").queue();
                }
                break;
            case "encrypt":
                String message = (e.getOption("message").getAsString());
                String aes = e.getOption("aes").getAsString();
                SecretKey key;

                if (!aes.equalsIgnoreCase("AES-128") && !aes.equalsIgnoreCase("AES-192") && !aes.equalsIgnoreCase("AES-256")) {
                    e.reply("Invalid encryption method: \"" + aes + "\" does not match AES-128, AES-192, or AES-256.").queue();
                } else {
                    try {
                        if (e.getOption("key") != null) {
                            byte[] inputKeyBytes = e.getOption("key").getAsString().getBytes();
                            key = new SecretKeySpec(inputKeyBytes, 0, inputKeyBytes.length, "AES");
                        } else {
                            key = generateKey(Integer.parseInt(aes.substring(4)));
                        }

                        String keyString = DatatypeConverter.printBase64Binary(key.getEncoded());
                        e.reply("Your encrypted message is: " + encryptMessage(key, message) + "\n\nYour secret key is: ||" + keyString + "||").queue();
                    } catch (GeneralSecurityException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                break;
            case "decrypt":
                message = e.getOption("message").getAsString();

                try {
                    byte[] keyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                    key = new SecretKeySpec(keyBytes, "AES");

                    e.reply("Your decrypted message is: ||" + decryptMessage(key, message) + "||").queue();
                } catch (GeneralSecurityException ex) {
                    throw new RuntimeException(ex);
                }
                break;
        }
    }

    public String convertBits(String type, String data) {
        switch (type) {
            case "base64":
                return stringToBase64(bitsToString(data));
            case "hex":
                return stringToHex(bitsToString(data));
            case "string":
                return bitsToString(data);
            case "bits":
                return data;
        }
        return ("Incorrect value: \"" + type + "\" does not match Bits, String, Hex, or Base64.");
    }

    public String convertString(String type, String data) {
        switch (type) {
            case "base64":
                return stringToBase64(data);
            case "hex":
                return stringToHex(data);
            case "string":
                return data;
            case "bits":
                return stringToBits(data);
        }
        return ("Incorrect value: \"" + type + "\" does not match Bits, String, Hex, or Base64.");
    }

    public String convertHex(String type, String data) {
        switch (type) {
            case "base64":
                return stringToBase64(hexToString(data));
            case "hex":
                return data;
            case "string":
                return hexToString(data);
            case "bits":
                return stringToBits(hexToString(data));
        }
        return ("Incorrect value: \"" + type + "\" does not match Bits, String, Hex, or Base64.");
    }

    public String convertBase64(String type, String data) {
        switch (type) {
            case "base64":
                return data;
            case "hex":
                return stringToHex(base64ToString(data));
            case "string":
                return base64ToString(data);
            case "bits":
                return stringToBits(base64ToString(data));
        }
        return ("Incorrect value: \"" + type + "\" does not match Bits, String, Hex, or Base64.");
    }

    public String bitsToString(String bits) {
        bits = bits.replaceAll(" ", "");
        byte[] bytes = new byte[bits.length() / 8];

        for (int i = 0; i < bits.length() - 7; i += 8) {
            bytes[i / 8] = (byte) Integer.parseInt(bits.substring(i, i + 8), 2);
        }

        String str = new String(bytes, StandardCharsets.UTF_8);
        return str;
    }

    public String stringToBits(String str) {
        String bits = "";
        String value = "";

        for (int i = 0; i < str.length(); i++) {
            value = String.format("%8s", Integer.toBinaryString(str.charAt(i))).replaceAll(" ", "0");
            bits += value + " ";
        }

        return bits;
    }

    public String hexToString(String hex) {
        return new String(DatatypeConverter.parseHexBinary(hex));
    }

    public String stringToHex(String str) {
        byte[] bytes = str.getBytes();
        return DatatypeConverter.printHexBinary(bytes);
    }

    public String base64ToString(String base64) {
        return new String(DatatypeConverter.parseBase64Binary(base64));
    }

    public String stringToBase64(String str) {
        byte[] bytes = str.getBytes();
        return DatatypeConverter.printBase64Binary(bytes);
    }

    public SecretKey generateKey(int aes) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(aes);
        SecretKey key = generator.generateKey();
        return key;
    }

    public String encryptMessage(SecretKey inputKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, inputKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptMessage(SecretKey key, String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }
}