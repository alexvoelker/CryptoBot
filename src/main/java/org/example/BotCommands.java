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
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class BotCommands extends ListenerAdapter {

    ArrayList<Message> messages = new ArrayList<>();
    ArrayList<UserKey> userKeys = new ArrayList<>();

    @Override
    public void onReady(@NotNull ReadyEvent readyEvent) {
        ArrayList<CommandData> commands = new ArrayList<>();

        //testing
        commands.add(Commands.slash("hi", "testing"));

        // About/Help
        commands.add(Commands.slash("about", "The bot command about page!"));
        commands.add(Commands.slash("help", "A help page to learn how commands work")
                .addOption(OptionType.STRING, "command", "the command to learn more about", false));

        // Datatype conversions
        commands.add(Commands.slash("convert", "Convert data from Type1 to Type2")
                .addOption(OptionType.STRING, "type1", "Input data type (Bits, String, Hex, Base64)", true)
                .addOption(OptionType.STRING, "type2", "Output data type (Bits, String, Hex, Base64)", true)
                .addOption(OptionType.STRING, "data", "Data to be converted", true));


        //AES symmetric key encryption
        commands.add(Commands.slash("message", "Encrypt a message for a user")
                .addOption(OptionType.STRING, "message", "Input message", true)
                .addOption(OptionType.STRING, "user", "Input user", true));

        //Public-private key encryption
        commands.add(Commands.slash("generate_keys", "Generate an asymmetric keypair"));
        commands.add(Commands.slash("get_public_key", "Generate an asymmetric keypair")
                .addOption(OptionType.STRING, "user", "User to get the public key from", true));
        commands.add(Commands.slash("decrypt_message", "Decrypt a message from another user")
                .addOption(OptionType.STRING, "id", "ID of the message", true));

        //Encryption and decryption (either symmetric or asymmetric)
        commands.add(Commands.slash("encrypt", "Encrypt a message")
                .addOption(OptionType.STRING, "message", "Message to be encrypted", true)
                .addOption(OptionType.STRING, "type", "Type of encryption (asymmetric or symmetric)", true)
                .addOption(OptionType.STRING, "mode", "Mode: AES-128, AES-192, AES-256, RSA (defaults to AES-128 or RSA)", false)
                .addOption(OptionType.STRING, "key", "Key for encryption (auto generated if none provided)", false));
        commands.add(Commands.slash("decrypt", "Decrypt a message")
                .addOption(OptionType.STRING, "message", "Message to be decrypted", true)
                .addOption(OptionType.STRING, "type", "Type of encryption (asymmetric or symmetric)", true)
                .addOption(OptionType.STRING, "key", "Private Key for decryption", false));

        // Hashing Functionality
        commands.add(Commands.slash("hash", "Hash a message")
                .addOption(OptionType.STRING, "message", "Input message", true)
                .addOption(OptionType.STRING, "hash_algorithm", "Hash Algorithm: MD5, SHA-1, SHA-256", true));

        readyEvent.getJDA().updateCommands().addCommands(commands).queue();

    }

    @Override
    public void onSlashCommandInteraction(SlashCommandInteractionEvent e) {
        String reply = "error";
        switch (e.getName()) {
            case "hi":
                e.reply("hi").queue();
                break;
            case "help":
                try {
                    String helpCommand = e.getOption("command").getAsString();
                    // Help page for a specific bot command

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
                                    "> Allows for messages to be encrypted using specific asymmetric-key algorithms\n\n" +
                                    "Example: `/encrypt asymmetric Hello World! RSA-1024`\n";
                            break;
                        case "decrypt": // TODO finish this when the discord channel is updated
                            reply = "## CryptoBot Symmetric-key Implementations: Decryption\n" +
                                    "```/decrypt symmetric [message] [secret key]```  \n" +
                                    "> Decrypts the message cipher text outputted from CryptoBot with the corresponding secret key\n" +
                                    " \n" +
                                    "Example: `/decrypt symmetric ylj6IYAW0chOtmIRjbjITA== TiyllEm0hqJapmZpljAh1Q==`\n" +
                                    " \n## CryptoBot Asymmetric-Key Implementations: Decryption\n" +
                                    "**Encryption Mode:** RSA \n" +
                                    "```/decrypt asymmetric [message] [private key]```\n" +
                                    "> Decrypts the message cipher text outputted from CryptoBot with " +
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
                                    "\nExample: `/receive 1`";
                            ;
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
                    reply = convertBits(type2.toLowerCase(), data);
                } else if (type1.equalsIgnoreCase("string")) {
                    reply = convertString(type2.toLowerCase(), data);
                } else if (type1.equalsIgnoreCase("hex")) {
                    reply = convertHex(type2.toLowerCase(), data);
                } else if (type1.equalsIgnoreCase("base64")) {
                    reply = convertBase64(type2.toLowerCase(), data);
                } else {
                    e.reply("Incorrect value: \"" + type1 + "\" does not match Bits, String, Hex, or Base64.").queue();
                }

                if (reply.length() > 2000) {
                    e.reply("Sorry! The output will be too long. Try shortening your input.");
                } else {
                    e.reply(reply).queue();
                }

                break;
            case "encrypt":
                String type = (e.getOption("type").getAsString());
                message = (e.getOption("message").getAsString());
                String mode = "";

                if (e.getOption("mode") != null) {
                    mode = e.getOption("mode").getAsString();
                } else if (type.equalsIgnoreCase("symmetric")) {
                    mode = "AES-128";
                } else if (type.equalsIgnoreCase("asymmetric")) {
                    mode = "RSA";
                }

                SecretKey key;
                boolean found = false;

                mode = mode.replaceAll("AES-", "");
                String[] validModesSymmetricArray = {"128", "192", "256"};
                String[] validModesAsymmetricArray = {"RSA"};
                List<String> validModesSymmetric = Arrays.asList(validModesSymmetricArray);
                List<String> validModesAsymmetric = Arrays.asList(validModesAsymmetricArray);

                if (type.equalsIgnoreCase("symmetric")) {
                    try {
                        if (!validModesSymmetric.contains(mode)) {
                            reply = "Your specified mode of `" + mode + "` is not a valid mode for asymmetric encryption. Valid modes include: AES-128, AES-196, and AES-256";
                        } else if (e.getOption("key") != null) {
                            byte[] inputKeyBytes = e.getOption("key").getAsString().getBytes();
                            key = new SecretKeySpec(inputKeyBytes, 0, inputKeyBytes.length, "AES");
                            reply = "Your encrypted message is: " + encryptMessageSymmetric(key, message);
                        } else {
                            key = generateSymmetricKey(Integer.parseInt(mode));
                            String keyString = DatatypeConverter.printBase64Binary(key.getEncoded());
                            reply = "Your encrypted message is: " + encryptMessageSymmetric(key, message) + "\n\nYour secret key is: ||" + keyString + "||";
                        }
                    } catch (GeneralSecurityException ex) {
                        throw new RuntimeException(ex);
                    }
                } else if (type.equalsIgnoreCase("asymmetric")) {
                    try {
                        if (message.getBytes().length > 117) {
                            reply = "Sorry! Your message was too long. We can only support up to 117 bytes of information for asymmetric encryption.\n" +
                                    "Your input included `" + message.getBytes().length + "` of information. Try shortening your message.";
                        } else if (!validModesAsymmetric.contains(mode)) {
                            reply = "Your specified mode of `" + mode + "` is not a valid mode for asymmetric encryption. Valid modes include: RSA";
                        } else if (e.getOption("key") == null) {
                            found = false;
                            for (int i = 0; i < userKeys.size(); i++) {
                                if (userKeys.get(i).getUser().equals(e.getUser().getId())) {
                                    reply = "Your encrypted message is: " + userKeys.get(i).encryptMessageAsymmetric(message);
                                    found = true;
                                }
                            }

                            if (!found) {
                                KeyPair keyPair = generateAsymmetricKeys();
                                PrivateKey privateKey = keyPair.getPrivate();
                                PublicKey publicKey = keyPair.getPublic();
                                userKeys.add(new UserKey(e.getUser().getId(), privateKey, publicKey));

                                String privateKeyString = DatatypeConverter.printBase64Binary(privateKey.getEncoded());
                                e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("Your private key is: `" + privateKeyString + "`")).queue();

                                String publicKeyString = DatatypeConverter.printBase64Binary(publicKey.getEncoded());
                                reply = "Your encrypted message is: " + UserKey.encryptMessageAsymmetric(publicKey, message) + "\n\nThe public key used to encrypt this is: `" + publicKeyString + "`";
                            }

                        } else {
                            byte[] publicKeyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            PublicKey publicKey = keyFactory.generatePublic(keySpec);

                            reply = "Your encrypted message is: " + UserKey.encryptMessageAsymmetric(publicKey, message);
                        }
                    } catch (GeneralSecurityException ex) {
                        throw new RuntimeException(ex);
                    }
                } else {
                    reply = "The specified type of `" + type + "` does not match \"symmetric\" or \"asymmetric\"";
                }

                if (reply.length() > 2000) {
                    e.reply("Sorry! The output will be too long. Try shortening your input.");
                } else {
                    e.reply(reply).queue();
                }

                break;
            case "decrypt":
                message = e.getOption("message").getAsString();
                type = (e.getOption("type").getAsString());

                if (type.equalsIgnoreCase("symmetric")) {
                    try {
                        if (e.getOption("key") != null) {
                            byte[] keyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                            key = new SecretKeySpec(keyBytes, "AES");
                            reply = "Your decrypted message is: ||" + decryptMessageSymmetric(key, message) + "||";
                        } else {
                            reply = "You will need to specify a key for symmetric decryption.";
                        }
                    } catch (GeneralSecurityException ex) {
                        throw new RuntimeException(ex);
                    }
                } else if (type.equalsIgnoreCase("asymmetric")) {
                    if (e.getOption("key") == null) {
                        found = false;

                        for (int i = 0; i < userKeys.size(); i++) {
                            if (userKeys.get(i).getUser().equals(e.getUser().getId())) {
                                try {
                                    reply = "Your decrypted message is: " + userKeys.get(i).decryptMessageAsymmetric(message);
                                    found = true;
                                } catch (GeneralSecurityException ex) {
                                    throw new RuntimeException(ex);
                                }
                            }
                        }

                        if (!found) {
                            reply = "You do not have a private key associated with your ID! Try `/generate_keys` to get a key, or add a private key to this message to decrypt with.";
                        }

                    } else {
                        try {
                            byte[] privateKeyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

                            reply = "Your decrypted message is: ||" + UserKey.decryptMessageAsymmetric(privateKey, message) + "||";
                        } catch (GeneralSecurityException ex) {
                            throw new RuntimeException(ex);
                        }
                    }
                } else {
                    reply = "The specified type of `" + type + "` does not match \"symmetric\" or \"asymmetric\"";
                }

                if (reply.length() > 2000) {
                    e.reply("Sorry! The output will be too long. Try shortening your input.");
                } else {
                    e.reply(reply).queue();
                }

                break;
            case "message":
                message = e.getOption("message").getAsString();
                String user = e.getOption("user").getAsString();
                String cipher = "";

                try {
                    found = false;
                    for (int i = 0; i < userKeys.size(); i++) {
                        if (userKeys.get(i).getUser().equals(e.getUser().getId())) {
                            cipher = userKeys.get(i).encryptMessageAsymmetric(message);
                            found = true;
                        }
                    }

                    if(found){
                        Message msg = new Message("<@" + e.getUser().getId() + ">", user, cipher);
                        reply = msg.getReceiver() + " you were just sent a message from " + msg.getSender() + "\nThe cipher text is: " + msg.getCipher() +
                                "\n\nYou can use the /decrypt command to decrypt the cipher with your private key, or use the following command:\n`/decrypt_message " + msg.getId() + "`";
                        if (reply.length() > 2000) {
                            e.reply("Sorry! The output will be too long. Try shortening your input.");
                        } else {
                            messages.add(msg);
                        }
                    } else {
                        reply = "The receiver does not have a pair of keys generated. Please let them know to run the command `/generate_keys`";
                    }

                    e.reply(reply).queue();

                } catch (GeneralSecurityException ex) {
                    throw new RuntimeException(ex);
                }
                break;
            case "decrypt_message":
                String id = e.getOption("id").getAsString();
                String userId = "<@" + e.getUser().getId() + ">";
                found = false;

                for (int i = 0; i < messages.size(); i++) {
                    if (messages.get(i).getId().equals(id)) {
                        if (userId.equals(messages.get(i).getReceiver())) {
                            for (int j = 0; j < userKeys.size(); j++) {
                                if (userKeys.get(i).getUser().equals(e.getUser().getId())) {
                                    try {
                                        found = true;
                                        e.reply("The decrypted message is:\n" + userKeys.get(j).decryptMessageAsymmetric(messages.get(i).getCipher())).queue();
                                    } catch (GeneralSecurityException ex) {
                                        throw new RuntimeException(ex);
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
                if(!found){
                    e.reply("You're not the intended receiver for this message!").queue();
                }
                break;
            case "generate_keys":
                userId = e.getUser().getId();
                UserKey userKey = null;
                try {
                    for (int i = 0; i < userKeys.size(); i++) {
                        if (userKeys.get(i).getUser().equals(userId)) {
                            userKey = userKeys.get(i);
                            userKeys.remove(i);
                        }
                    }
                    KeyPair keyPair = generateAsymmetricKeys();
                    String publicKey = new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded()));
                    String privateKey = new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded()));
                    if (userKey != null) {
                        userKey.setPrivateKey(keyPair.getPrivate());
                        userKey.setPublicKey(keyPair.getPublic());
                        e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("Your old public and private keys are no longer associated with your ID." +
                                " The new private key is: `" + privateKey + "`")).queue();
                    } else {
                        userKey = new UserKey(userId, keyPair.getPrivate(), keyPair.getPublic());
                        e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("Your private key is: `" + privateKey + "`")).queue();
                    }
                    userKeys.add(userKey);
                    e.reply("Your private key has been DM'd to you.\nYour public key is: `" + publicKey + "`").queue();
                } catch (NoSuchAlgorithmException ex) {
                    throw new RuntimeException(ex);
                }
                break;
            case "get_public_key":
                userId = e.getOption("user").getAsString();
                userId = userId.substring(2, userId.length() - 1);

                found = false;
                for (int i = 0; i < userKeys.size(); i++) {
                    if (userKeys.get(i).getUser().equals(userId)) {
                        reply = "This user's public key is: " + userKeys.get(i).getPublicKey();
                        found = true;
                    }
                }

                if (!found) {
                    reply = "Could not find a public key associated with this user. Maybe ask them to generate one.";
                }

                e.reply(reply).queue();
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
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decryptMessageSymmetric(SecretKey secretKey, String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        Cipher cipher = Cipher.getInstance("AES");
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
}