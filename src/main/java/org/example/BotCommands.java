package org.example;

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
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;

public class BotCommands extends ListenerAdapter {

    ArrayList<Message> messages = new ArrayList<>();

    @Override
    public void onReady(@NotNull ReadyEvent readyEvent){
        ArrayList<CommandData> commands = new ArrayList<>();

        //testing
        commands.add(Commands.slash("hi", "testing"));

        // About/Help
        commands.add(Commands.slash("about", "The bot command about page!"));
        commands.add(Commands.slash("help", "A help page to learn how commands work")
                .addOption(OptionType.STRING, "command", "the command to learn more about", false));

        // Datatype conversions
        commands.add(Commands.slash("convert", "Convert data from Type1 to Type2")
                .addOption(OptionType.STRING,"type1", "Input data type", true)
                .addOption(OptionType.STRING,"type2", "Output data type", true)
                .addOption(OptionType.STRING,"data", "Data to be converted", true));

        // AES symmetric key encryption
        commands.add(Commands.slash("encrypt", "Encrypt a message")
                .addOption(OptionType.STRING,"message", "Message to be encrypted", true)
                .addOption(OptionType.STRING,"aes", "Mode of encryption: AES-128, AES-192, AES-256", true)
                .addOption(OptionType.STRING,"key", "Private Key for encryption (auto generated if none provided)", false));
        commands.add(Commands.slash("decrypt", "Decrypt a message")
                .addOption(OptionType.STRING,"message", "Message to be decrypted", true)
                .addOption(OptionType.STRING,"key", "Private Key for decryption", true));
        commands.add(Commands.slash("message", "Encrypt a message for a user")
                .addOption(OptionType.STRING,"message", "Input message", true)
                .addOption(OptionType.STRING,"user", "Input user", true)
                .addOption(OptionType.STRING,"encryption", "Mode of encryption: AES-128, AES-192, AES-256", true));
        commands.add(Commands.slash("receive", "Receive key")
                .addOption(OptionType.STRING,"id", "ID", true));


        // Hashing Functionality
        commands.add(Commands.slash("hash", "Hash a message")
                .addOption(OptionType.STRING, "message", "Input message", true)
                .addOption(OptionType.STRING, "hash_algorithm", "Hash Algorithm: MD5, SHA-1, SHA-256", true));


        readyEvent.getJDA().updateCommands().addCommands(commands).queue();

    }

    @Override
    public void onSlashCommandInteraction(SlashCommandInteractionEvent e) {
        switch (e.getName()) {
            case "hi":
                e.reply("hi").queue();
                break;
            case "help":
                try {
                    String helpCommand = e.getOption("command").getAsString();
                    // Help page for a specific bot command

                    String reply;
                    switch (helpCommand) {
                        case "about":
                            reply = "Run the `about` command for some information about this discord bot.";
                            break;
                        case "convert":
                            reply = "## Encoding and Decoding" +
                                    "This a system where different encoding standards can be used to convert plaintext into different types of data\n" +
                                    "\n" +
                                    "**Supported Datatypes**: String, Hex (hexadecimal), Bits (binary), Base64 \n\n" +
                                    "## Data types\n" +
                                    "### Bits (binary)\n" +
                                    "Very basic form of data with a Base-2 (2 character) structure where all everything is represented by either a 1 or 0\n" +
                                    "### String\n" +
                                    "Sequence of characters that is in a human-readable form\n" +
                                    "### Hex\n" +
                                    "Form of data in a Base-16 (16 character) structure where data is represented by 0-9 and A-F\n" +
                                    "### Base64\n" +
                                    "Form of data in a Base-64 (64 character) structure with the data form defined by RFC 4648\n\n" +
                                    "## Usage\n" +
                                    "**Encoding Modes**: *Bits, String, Hex, Base64*\n" +
                                    "```/convert [input type] [output type] data```\n" +
                                    "> Allows for data to be converted using different encoding standards\n" +
                                    "Example: `/convert String Base64 Hello World!`";
                            break;
                        case "encrypt": // TODO finish this when the discord channel is updated
                            reply = "## CryptoBot Symmetric-key Implementations: Encryption\n" +
                                    "**Encryption Modes:** AES-128, AES-192, AES-256\n" +
                                    "*the number determines the bits of the outputted secret key (AES-256 -> 256 bits)*\n" +
                                    " \n" +
                                    "```/encrypt symmetric [message] [encryption]```  \n" +
                                    "> Allows for messages to be encrypted using specific symmetric-key algorithms\n" +
                                    " \n" +
                                    "Example: `/encrypt symmetric Hello World! AES-128`\n\n" +
                                    "## CryptoBot Asymmetric-Key Implementations: Encryption\n" +
                                    "**Encryption Modes:** RSA-1024, RSA-2048, RSA-3072, RSA-4096 \n" +
                                    "The number determines the bits of the outputted secret key (RSA-2048 -> 2048 bits)\n" +
                                    "```/encrypt asymmetric [message] [encryption]```\n" +
                                    "> Allows for messages to be encrypted using specific asymmetric-key algorithms\n" +
                                    "Example: `/encrypt asymmetric Hello World! RSA-1024`\n";
                            break;
                        case "decrypt": // TODO finish this when the discord channel is updated
                            reply = "## CryptoBot Symmetric-key Implementations: Decryption\n" +
                                    "```/decrypt symmetric [message] [secret key]```  \n" +
                                    "> Decrypts the message cipher text outputted from CryptoBot with the corresponding secret key\n" +
                                    " \n" +
                                    "Example: `/decrypt symmetric ylj6IYAW0chOtmIRjbjITA== TiyllEm0hqJapmZpljAh1Q==`\n" +
                                    " \n## CryptoBot Asymmetric-Key Implementations: Encryption\n" +
                                    "**Encryption Modes:** RSA-1024, RSA-2048, RSA-3072, RSA-4096 \n" +
                                    "```/decrypt asymmetric [message] [private key]```\n" +
                                    "Decrypts the message cipher text outputted from CryptoBot with " +
                                    "the corresponding private key\n\n" +
                                    "Example: `/decrypt asymmetric ylj6IYAW0chOtmIRjbjITA==` `TiyllEm0hqJapmZpljAh1Q==`";
                            break;
                        case "message":
                            reply = "```/message [message text] [discord user] [encryption]```\n" +
                                    "> Sends an encrypted message to a discord user using specific symmetric-key algorithms\n" +
                                    "\n**Supported Encryption Algorithms:** AES-128, AES-192, AES-256\n" +
                                    "Example: `/message Hello World! @user AES-128`\n" +
                                    " \n```/receive [message id]```\n" +
                                    "> Decrypts a message sent from another user using the message id received from the CryptoBot\n" +
                                    "\nExample: `/receive 1`";;
                            break;
                        case "receive":
                            reply = "```/receive [message id]```\n" +
                                    "Receives a message sent from another user using the message id received from the CryptoBot\n" +
                                    "Example: `/receive 1`";
                            break;
                        case "hash":
                            reply = "Hashing is a system where an input (or ‘message’) is taken and returned as a fixed-size string of bytes. The output (or ‘hash’) is unique to each unique input. It’s a one-way function, meaning the data cannot be decrypted back from the hash.\n" +
                                    "*Examples: MD5, SHA-1, SHA-256, SHA-3, HMAC*\n\n" +
                                    "## Hashing Implementations\n" +
                                    "**Supported Hashing Algorithms:** MD5, SHA-1, SHA-256\n" +
                                    "The name determines the hashing algorithm used (SHA-256 -> SHA-256 algorithm)\n" +
                                    "```/hash [message] [hashing algorithm]```\n" +
                                    "> Allows for messages to be hashed using specific algorithms\n" +
                                    "Example:  `/hash Hello World! SHA-256`\n\n";
                            break;
                        case "verify":
                            reply = "Hashing is a system where an input (or ‘message’) is taken and returned as a fixed-size string of bytes. The output (or ‘hash’) is unique to each unique input. It’s a one-way function, meaning the data cannot be decrypted back from the hash.\n" +
                                    "*Examples: MD5, SHA-1, SHA-256, SHA-3, HMAC*\n\n" +
                                    "## Hashing Implementations\n" +
                                    "**Supported Hashing Algorithms:** MD5, SHA-1, SHA-256\n" +
                                    "```/verify [message] [hash] [hashing algorithm]```\n" +
                                    "> Verifies the message with the corresponding hash\n";
                            break;
                        default:
                            throw new IllegalArgumentException("Break towards the default help page");
                    }
                    e.reply("# " + helpCommand.toUpperCase() + " Documentation\n\n" + reply).queue();

                } catch (NullPointerException | IllegalArgumentException ex) {
                    // Catches if the input is null or not a valid command

                    // Default full help page
                    e.reply("# Welcome to the help page." +
                            "\nTo view a more detailed help message for a specific command, type `/help [command]`" +
                            "\nThe list of valid commands are:" +
                            "\n\n### `help`\n\tThis help page!\n\tParameters: `[command]`" +
                            "\n\n### `about`\n\tThe bot command about page!" +
                            "\n\n### `convert`\n\tConvert data from Type1 to Type2\n\tParameters: `[type1]` `[type2]` `[data]`" +
                            // TODO might need to change the encrypt and decrypt help when asymmetric is added
                            "\n\n### `encrypt`\n\tEncrypt a message\n\tParameters: `[type]` `[message]` `[aes]` `[key]`" +
                            "\n\n### `decrypt`\n\tDecrypt a message\n\tParameters: `[type]` `[message]` `[key]`" +
                            "\n\n### `message`\n\tEncrypt a message for a user\n\tParameters: `[message]` `[user]` `[encryption]`" +
                            "\n\n### `receive`\n\tReceive key\n\tParameters: `[ID]`" +
                            "\n\n### `hash`\n\tHash a message\n\tParameters: `[message]` `[hash_algorithm]`" +
                            "\n\n### `verify`\n\tVerify a hashed message\n\tParameters: `[message]` `[hash]` `[hash_algorithm]`").queue();
                }
                break;
            case "about":
                String response = "Thanks for using the CryptoBot! \n\n" +
                        "This is a cryptography tool, created by Group 2 in CNIT 370, to help you learn about " +
                        "encryption, decryption, and hashing in an active environment.\n\n" +
                        "We also have some data conversion tools for you to use! \n\tTry `/convert`" +
                        "\n\nIf you want to learn more about the commands this bot has to offer, try `/help`" +
                        "\n\nJoin our public discord server at: https://discord.gg/vhuZFkHkRc" +
                        "\n\nYou can view our sourcecode on our public GitHub repository: " +
                        "https://github.com/alexvoelker/CryptoBot";
                e.reply(response).queue();
                break;
            case "hash":
                String message = e.getOption("message").getAsString();
                String hash_algorithm = e.getOption("hash_algorithm").getAsString().toUpperCase();

                try {
                    MessageDigest messageDigest = MessageDigest.getInstance(hash_algorithm);

                    // Call the Java hashing function, which returns an array of bytes
                    byte[] digestOfMessage = messageDigest.digest(message.getBytes());

                    // Convert the array of bytes to a string.
                    String hashed_message = DatatypeConverter.printBase64Binary(digestOfMessage);

                    e.reply("Initial message: `" + message + "`\nHash Algorithm: `"
                            + hash_algorithm + "`\nHashed Message (in base64): `" + hashed_message + "`").queue();

                } catch (NoSuchAlgorithmException ex) {
                    e.reply("The specified hashing algorithm `" + hash_algorithm
                            + "` is invalid. Try: MD5, SHA-1 or SHA-256").queue();
                }
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
                message = (e.getOption("message").getAsString());
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
            case "message":
                message = e.getOption("message").getAsString();
                String user = e.getOption("user").getAsString();
                aes = e.getOption("encryption").getAsString();

                try {
                    key = generateKey(Integer.parseInt(aes.substring(4)));
                    String keyString = DatatypeConverter.printBase64Binary(key.getEncoded());
                    Message msg = new Message("<@" + e.getUser().getId() + ">", user, encryptMessage(key, message),keyString);
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