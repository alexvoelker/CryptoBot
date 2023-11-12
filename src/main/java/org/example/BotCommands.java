package org.example;

import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.entities.Activity;
import net.dv8tion.jda.api.entities.Guild;
import net.dv8tion.jda.api.entities.Member;
import net.dv8tion.jda.api.entities.User;
import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.events.session.ReadyEvent;
import net.dv8tion.jda.api.hooks.ListenerAdapter;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.CommandData;
import net.dv8tion.jda.api.interactions.commands.build.Commands;
import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.*;

import static org.example.Main.getJDA;

public class BotCommands extends ListenerAdapter {

    ArrayList<Message> messages = new ArrayList<>();

    @Override
    public void onReady(@NotNull ReadyEvent readyEvent){
        ArrayList<CommandData> commands = new ArrayList<>();

        //testing
        commands.add(Commands.slash("hi", "testing"));

        //datatype conversions
        commands.add(Commands.slash("convert", "Convert data from Type1 to Type2")
                .addOption(OptionType.STRING,"type1", "Input data type", true)
                .addOption(OptionType.STRING,"type2", "Output data type", true)
                .addOption(OptionType.STRING,"data", "Data to be converted", true));

        //AES symmetric key encryption
        commands.add(Commands.slash("message", "Encrypt a message for a user")
                .addOption(OptionType.STRING,"message", "Input message", true)
                .addOption(OptionType.STRING,"user", "Input user", true)
                .addOption(OptionType.STRING,"encryption", "Mode of encryption: AES-128, AES-192, AES-256", true));
        commands.add(Commands.slash("receive", "Receive key")
                .addOption(OptionType.STRING,"id", "ID", true));

        //Public-private key encryption
        commands.add(Commands.slash("generate_keys", "Generate a keypair"));

        //Encryption and decryption (either symmetric or asymmetric)
        commands.add(Commands.slash("encrypt", "Encrypt a message")
                .addOption(OptionType.STRING,"message", "Message to be encrypted", true)
                .addOption(OptionType.STRING,"type", "Type of encryption (asymmetric or symmetric)", true)
                .addOption(OptionType.STRING,"mode", "Mode: AES-128, AES-192, AES-256, RSA (defaults to AES-128 or RSA)", false)
                .addOption(OptionType.STRING,"key", "Key for encryption (necessary for asymmetric, auto generated if symmetric and none provided)", false));
        commands.add(Commands.slash("decrypt", "Decrypt a message")
                .addOption(OptionType.STRING,"message", "Message to be decrypted", true)
                .addOption(OptionType.STRING,"type", "Type of encryption (asymmetric or symmetric)", true)
                .addOption(OptionType.STRING,"key", "Private Key for decryption", true));

        readyEvent.getJDA().updateCommands().addCommands(commands).queue();

    }

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
                String type = (e.getOption("type").getAsString());
                String message = (e.getOption("message").getAsString());
                String mode = "";
                if (e.getOption("mode") != null) {
                    mode = e.getOption("mode").getAsString();
                } else if(type.equalsIgnoreCase("symmetric")){
                    mode = "AES-128";
                } else if(type.equalsIgnoreCase("asymmetric")) {
                    mode = "RSA";
                }
                SecretKey key;

                mode = mode.replaceAll("AES-", "");
                String[] validModesArray = {"128", "192", "256", "RSA"};
                List<String> validModes = Arrays.asList(validModesArray);

                if (!validModes.contains(mode)) {
                    e.reply("Invalid encryption method: \"" + mode + "\" does not match AES-128, AES-192, AES-256, or RSA.").queue();
                } else {
                    if(type.equalsIgnoreCase("symmetric")){
                        try {
                            if (e.getOption("key") != null) {
                                byte[] inputKeyBytes = e.getOption("key").getAsString().getBytes();
                                key = new SecretKeySpec(inputKeyBytes, 0, inputKeyBytes.length, "AES");
                            } else {
                                key = generateSymmetricKey(Integer.parseInt(mode));
                            }

                            String keyString = DatatypeConverter.printBase64Binary(key.getEncoded());
                            e.reply("Your encrypted message is: " + encryptMessageSymmetric(key, message) + "\n\nYour secret key is: ||" + keyString + "||").queue();
                        } catch (GeneralSecurityException ex) {
                            throw new RuntimeException(ex);
                        }
                    } else if(type.equalsIgnoreCase("asymmetric")){
                        try {
                            if (e.getOption("key") != null) {
                                KeyPair keyPair = generateAsymmetricKeys();
                                PrivateKey privateKey = keyPair.getPrivate();
                                PublicKey publicKey = keyPair.getPublic();

                                String privateKeyString = DatatypeConverter.printBase64Binary(privateKey.getEncoded());
                                e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("Your private key is: `" + privateKeyString + "`")).queue();

                                String publicKeyString = DatatypeConverter.printBase64Binary(publicKey.getEncoded());
                                e.reply("Your encrypted message is: " + encryptMessageAsymmetric(publicKey, message) + "\n\nThe public key used to encrypt this is: `" + publicKeyString + "`").queue();
                            } else {
                                byte[] publicKeyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(publicKeyBytes);
                                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                                PublicKey publicKey = keyFactory.generatePublic(keySpec);

                                e.reply("Your encrypted message is: " + encryptMessageAsymmetric(publicKey, message)).queue();
                            }
                        } catch (GeneralSecurityException ex) {
                            throw new RuntimeException(ex);
                        }
                    }
                }
                break;
            case "decrypt":
                message = e.getOption("message").getAsString();
                type = (e.getOption("type").getAsString());

                if(type.equalsIgnoreCase("symmetric")){
                    try {
                        byte[] keyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                        key = new SecretKeySpec(keyBytes, "AES");

                        e.reply("Your decrypted message is: ||" + decryptMessageSymmetric(key, message) + "||").queue();
                    } catch (GeneralSecurityException ex) {
                        throw new RuntimeException(ex);
                    }
                } else if(type.equalsIgnoreCase("asymmetric")){
                    try {
                        byte[] privateKeyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

                        e.reply("Your decrypted message is: ||" + decryptMessageAsymmetric(privateKey, message) + "||").queue();
                    } catch (GeneralSecurityException ex) {
                        throw new RuntimeException(ex);
                    }
                }
                break;
            case "message":
                message = e.getOption("message").getAsString();
                String user = e.getOption("user").getAsString();
                String aes = e.getOption("encryption").getAsString();

                try {
                    key = generateSymmetricKey(Integer.parseInt(aes.substring(4)));
                    String keyString = DatatypeConverter.printBase64Binary(key.getEncoded());
                    Message msg = new Message("<@" + e.getUser().getId() + ">", user, encryptMessageSymmetric(key, message),keyString);
                    messages.add(msg);

                    e.reply(msg.getReceiver() + " you were just sent a message from " + msg.getSender() + "\nThe cipher text is: " + msg.getCipher() +
                            "\n\nYou can discover the secret key by entering the following command:\n**/receive message " + msg.id + "**").queue();
                } catch (GeneralSecurityException ex) {
                    throw new RuntimeException(ex);
                }
                break;
            case "receive":
                String id = e.getOption("id").getAsString();
                user = "<@" + e.getUser().getId() + ">";

                for(int i = 0; i < messages.size(); i++){
                    if(messages.get(i).getId().equals(id)){
                        Message temp = messages.get(i);

                        if(user.equals(messages.get(i).getReceiver())){
                            e.reply("Check your DMs").queue();
                            e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("The secret key to message " + temp.getId() + " is : `" + temp.getKey() + "`")).queue();
                        } else {
                            e.reply("no").queue();
                        }
                    }
                }
                break;
            case "generate_keys":
                try {
                    KeyPair keyPair = generateAsymmetricKeys();
                    String publicKey = new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded()));
                    String privateKey = new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()));
                    e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("Your private key is: `" + privateKey + "`")).queue();
                    e.reply("Your private key has been DM'd to you.\nYour public key is: `" + publicKey + "`").queue();
                } catch (NoSuchAlgorithmException ex) {
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

    public SecretKey generateSymmetricKey(int aes) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(aes);
        SecretKey key = generator.generateKey();
        return key;
    }

    public String encryptMessageSymmetric(SecretKey secretKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptMessageSymmetric(SecretKey secretKey, String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    public static KeyPair generateAsymmetricKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.genKeyPair();
        return keyPair;
    }

    public String encryptMessageAsymmetric(PublicKey publicKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptMessageAsymmetric(PrivateKey privateKey, String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }
}