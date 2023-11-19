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

    ArrayList<Message> messages = new ArrayList<>(); // List that keeps track of all messages for receiving and decryption purposes
    ArrayList<UserKey> userKeys = new ArrayList<>(); // List that keeps track of all user's keys to associate a discord ID with a keypair for asymmetric encryption

    @Override
    public void onReady(@NotNull ReadyEvent readyEvent) {
        ArrayList<CommandData> commands = new ArrayList<>(); // List for all commands to be added

        //testing commands
        commands.add(Commands.slash("hi", "testing"));

        // About/Help commands
        commands.add(Commands.slash("about", "The bot command about page!"));
        commands.add(Commands.slash("help", "A help page to learn how commands work")
                .addOption(OptionType.STRING, "command", "the command to learn more about", false));

        // Datatype conversions
        commands.add(Commands.slash("convert", "Convert data from Type1 to Type2")
                .addOption(OptionType.STRING, "type1", "Input data type (Bits, String, Hex, Base64)", true)
                .addOption(OptionType.STRING, "type2", "Output data type (Bits, String, Hex, Base64)", true)
                .addOption(OptionType.STRING, "data", "Data to be converted", true));


        // AES symmetric key encryption commands
        commands.add(Commands.slash("message", "Encrypt a message for a user")
                .addOption(OptionType.STRING, "message", "Input message", true)
                .addOption(OptionType.STRING, "user", "Input user", true));

        // RSA asymmetric key encryption commands
        commands.add(Commands.slash("generate_keys", "Generate an asymmetric keypair"));
        commands.add(Commands.slash("get_public_key", "Get the public key of an asymmetric keypair")
                .addOption(OptionType.STRING, "user", "User to get the public key from", true));
        commands.add(Commands.slash("decrypt_message", "Decrypt a message from another user")
                .addOption(OptionType.STRING, "id", "ID of the message", true));

        // General encryption and decryption (either symmetric or asymmetric)
        commands.add(Commands.slash("encrypt", "Encrypt a message")
                .addOption(OptionType.STRING, "message", "Message to be encrypted", true)
                .addOption(OptionType.STRING, "type", "Type of encryption (asymmetric or symmetric)", true)
                .addOption(OptionType.STRING, "mode", "Mode: AES-128, AES-192, AES-256, RSA (defaults to AES-128 or RSA)", false)
                .addOption(OptionType.STRING, "key", "Key for encryption (auto generated if none provided)", false));
        commands.add(Commands.slash("decrypt", "Decrypt a message")
                .addOption(OptionType.STRING, "message", "Message to be decrypted", true)
                .addOption(OptionType.STRING, "type", "Type of encryption (asymmetric or symmetric)", true)
                .addOption(OptionType.STRING, "key", "Private Key for decryption", false));

        // Hashing commands
        commands.add(Commands.slash("hash", "Hash a message")
                .addOption(OptionType.STRING, "message", "Input message", true)
                .addOption(OptionType.STRING, "hash_algorithm", "Hash Algorithm: MD5, SHA-1, SHA-256", true));

        readyEvent.getJDA().updateCommands().addCommands(commands).queue();

    }

    @Override
    public void onSlashCommandInteraction(SlashCommandInteractionEvent e) {
        String reply = "error"; // defines the reply string to be error incase it doesn't get changed
        switch (e.getName()) {
            case "hi": // /hi
                e.reply("hi").queue(); // just respond with hi :)
                break;
            case "help": // /help {command}
                try {
                    String helpCommand = e.getOption("command").getAsString();
                    // Help page for a specific bot command

                    switch (helpCommand) { // goes through each possible {command} input
                        case "help":
                            throw new IllegalArgumentException("Break towards the default help page");
                        case "about":
                            reply = "Run the `about` command for some information about this discord bot.\n```/about```";
                            break;
                        case "convert":
                            reply = "## Encoding and Decoding\n" +
                                    "This a system where different encoding standards can be used to convert plaintext into different types of data\n" +
                                    "**Supported Datatypes**: String, Hex (hexadecimal), Bits (binary), Base64 \n\n" +
                                    "## Data types\n\n" +
                                    "### Bits (binary)\n\n" +
                                    "> Very basic form of data with a Base-2 (2 character) structure where all everything is represented by either a 1 or 0\n" +
                                    "### String\n\n" +
                                    "> Sequence of characters that is in a human-readable form\n" +
                                    "### Hex\n\n" +
                                    "> Form of data in a Base-16 (16 character) structure where data is represented by 0-9 and A-F\n" +
                                    "### Base64\n\n" +
                                    "> Form of data in a Base-64 (64 character) structure with the data form defined by RFC 4648\n\n" +
                                    "## Usage\n" +
                                    "**Encoding Modes**: *Bits, String, Hex, Base64*\n" +
                                    "```/convert type1:[input type] type2:[output type] data:[data]```\n\n" +
                                    "> Allows for data to be converted using different encoding standards\n\n" +
                                    "Example: ```/convert type1:String type2:Base64 data:Hello World!```";
                            break;
                        case "generate_keys":
                            reply = "Generate a public-private keypair. " +
                                    "\n\nThe CryptoBot will message you your private key, and send your public key in " +
                                    "the channel that this command is executed in. " +
                                    "\n\nAnyone can encrypt messages to you using this generated public key." +
                                    "```/generate_keys```";
                            break;
                        case "get_public_key":
                            reply = "After a user generates a key using the `/generate_keys` command, " +
                                    "this retrieves that user's public key.\n\n" +
                                    "```/get_public_key user:[User]```\n\n" +
                                    "Example: ```/get_public_key user:@jas_0_3```";
                            break;
                        case "decrypt_message":
                            reply = "Decrypt an encrypted message sent to you using `/message @[YOUR USERNAME]`." +
                                    "\n\n> After you generate a public-private key-pair using the `/generate_keys` " +
                                    "command, other users can encrypt messages and send them to you using the `/message` command." +
                                    "\n\n```/decrypt_message id:[id]" +
                                    "\n\nExample: ```/decrypt_message id:1```" +
                                    "\n\n> If a message exists for you with an id of 1, it will be decrypted using your " +
                                    "private key.";
                            break;
                        case "message":
                            reply = "```/message message:[message] user:[Username]```\n" +
                                    "> Encrypts a message using the recipient’s public key and sends it to them, " +
                                    "ensuring secure communication through RSA asymmetric encryption.\n\n" +
                                    "Example: ```/message message:Hello World! user:@jas_0_3```\n";
                            break;
                        case "encrypt":
                            reply = "## CryptoBot Symmetric-key Encryption\n" +
                                    "Symmetric-key cryptography is a system where one key is used to both encrypt and decrypt information.\n" +
                                    "**Supported Encryption Modes:** AES-128, AES-192, AES-256\n" +
                                    "*the number determines the bits of the outputted secret key (AES-256 -> 256 bits)*\n\n" +
                                    "```/encrypt type:symmetric message:[message] mode:[encryption type]```\n" +
                                    "> Allows for messages to be encrypted using specific symmetric-key algorithms.\n\n" +
                                    "Example: ```/encrypt type:symmetric message:Hello World! mode:AES-128```\n\n" +
                                    "## CryptoBot Asymmetric-Key Encryption\n" +
                                    "**Encryption Modes:** RSA \n" +
                                    "```/encrypt message:[message] type:[type] mode:[mode] key:[key]```\n\n" +
                                    "> Allows for messages to be encrypted using specific asymmetric-key algorithms. " +
                                    "Entering mode and key are optional as it defaults to RSA. " +
                                    "A public-private keypair will be autogenerated for you if one doesn't currently exist.\n\n" +
                                    "Example: ```/encrypt message:Hello World! type:asymmetric```\n";
                            break;
                        case "decrypt":
                            reply = "## CryptoBot Symmetric-key Decryption\n" +
                                    "Symmetric-key cryptography is a system where one key is used to both encrypt and decrypt information.\n" +
                                    "```/decrypt type:symmetric message:[message] key:[secret key]```\n" +
                                    "> Decrypts the message cipher text outputted from CryptoBot with the corresponding secret key.\n\n" +
                                    "Example: ```/decrypt type:symmetric message:T6ZeaZZibJK6S+wy7iqBCg== key:kLllJ2QlD1HwnnZSERakJw==```\n\n" +

                                    "## CryptoBot Asymmetric-Key Decryption\n" +
                                    "Asymmetric-key cryptography is a system where a pair of keys is used to encrypt and decrypt information. " +
                                    "One key is public and can be shared with everyone, while the other key is private and is kept secret.\n\n" +
                                    "```/decrypt type:asymmetric message:[message] key:[key]```\n\n" +
                                    "> Decrypts the message cipher text outputted from CryptoBot with the corresponding key. " +
                                    "If no key is provided, the private key associated with your discord account will be used.\n\n" +
                                    "Example: ```/decrypt message:bDffmpRQsXwn3Dx1L+uhWax+2JywSxjbBT76BDWeGZMictsh2q4hSQzIEdIUA1lGuSbi" +
                                    "zu/ZGWqEviQKNam4Qbx5NX86/FcG4q73AwTPxBns46AcfesWmB50nrnnhCCQUc2uCpQB8JVEe/yMkcMcvamh2f1X5njkHvAZq" +
                                    "AFc4f8= type:asymmetric key:MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAIraK4nTQA3HvqtdfGZ/P" +
                                    "o6oe/CHZOq5IjdSLOQ1oH+QT1xboReXjKsv/rEiXmIWIxPIDClYoEG/bfLqXkguRYuZ5FiWoxO7HV+9wJof+fvX87nXBlVdt9" +
                                    "xHm89MIfd2aFhuzjeiSK8KRS+qKIqvcVXwmNaMBCAF6hTz71zrzxapAgMBAAECgYAwlAi0dQiNaasfCBt8PptTzMVjzvKzHid" +
                                    "G5ISZKNvolUP2o4YWG2rW/3kjXstXlLgb9RqwInYa2o7sdCudJDcnCL6+DWgeVTzaDNbbh4//GtM91fOXO5f9WME25hVGIaEo" +
                                    "MwuyG2x3kuzuWtugeB0Fp0jfg7ZVL722crZ85qon6wJBAP57j0Xa33u5nQzo6YKj2GbS46JGTniexTbi0NCrY2LlLWBmmS3AF" +
                                    "N/NuDpbhPl9cjLlWZGR+BhzL1JMW5/Jy9cCQQCLrhzva4q5J5l497UZKch1ikuZjMKXD/UqS7PNBzneVzrL/uNhw6Bz+8alBQ" +
                                    "0JuZDE+CaGkImWmcqiiUeAbeF/AkAF/NZEKIA1owpk8V39Kum+kZu1h7307JdrUS7kmgO+ofHNYNydzPUwxuBczyZz0FXNiMP" +
                                    "wvuR9fshQQWeufMsFAkBxD+ZsBeisJtmbiSYV0DRqsB6xk7aPAGO6cLyBYS/+QS1eolr7b5YZS9tnB8ed7463YQYONkConqPf" +
                                    "HK+7zTWRAkAqybH/6JBiDk72eVD2L0gjXekaqG6JJBOHZ3okBQIU82sQUNiIz7FIwTvZFkuJnryewnkmneIZPJK08DIrGMko```";
                            break;

                        case "hash":
                            reply = "Hashing is a system where an input (or ‘message’) is taken and returned as a fixed-size string of bytes. " +
                                    "The output (or ‘hash’) is unique to each unique input. It’s a one-way function, meaning the data cannot be decrypted back from the hash.\n" +
                                    "## Hashing Implementations\n" +
                                    "**Supported Hashing Algorithms:** MD5, SHA-1, SHA-256\n" +
                                    "The name determines the hashing algorithm used (SHA-256 -> SHA-256 algorithm)\n" +
                                    "```/hash message:[message] hash_algorithm:[hashing algorithm]```\n\n" +
                                    "> Allows for messages to be hashed using specific algorithms\n\n" +
                                    "Example:  ```/hash message:Hello World! hash_algorithm:SHA-256```\n\n";
                            break;
                        default:
                            e.reply("Invalid help page. To view a list of valid commands type ```/help```").queue();
                            throw new IllegalArgumentException("Break towards the default help page");
                    }
                    e.reply("# " + helpCommand.toUpperCase() + " Documentation\n\n" + reply).queue();

                } catch (NullPointerException | IllegalArgumentException ex) {
                    // Catches if the input is null or not a valid command

                    // Default full help page
                    e.reply("# Welcome to the help page." +
                            "\nTo view a more detailed help message for a specific command, type: \n\t```/help command:[command]```\n" +
                            "Example: ```/help command:about```\n\n" +
                            "> The example command here would display the help documentation on the *about* page.\n" +
                            "\n## The list of valid commands are:" +
                            "\n### help\n\tDescription:  This help page!\n\tParameters: `[command]`" +
                            "\n### about\n\tDescription:  The bot command about page!" +
                            "\n### convert\n\tDescription:  Convert data from Type1 to Type2\n\tParameters: `[type1]` `[type2]` `[data]`" +
                            "\n### message\n\tDescription:  Encrypt a message for a user\n\tParameters: `[message]` `[user]`" +
                            "\n### encrypt\n\tDescription:  Encrypt a message\n\tParameters: `[message]` `[type]` `[mode]` `[key]`" +
                            "\n### decrypt\n\tDescription:  Decrypt a message\n\tParameters: `[message]` `[type]` `[key]`" +
                            "\n### generate_keys\n\tDescription:  Generate an asymmetric keypair" +
                            "\n### get_public_key\n\tDescription:  Get the public key of an asymmetric keypair\n\tParameters: `[user]`" +
                            "\n### decrypt_message\n\tDescription:  Decrypt a message from another user\n\tParameters: `[id]`" +
                            "\n### hash\n\tDescription:  Hash a message\n\tParameters: `[message]` `[hash_algorithm]`").queue();
                }
                break;
            case "about": // /about
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
            case "hash": // /hash {message} {hash_algorithm}
                String message = e.getOption("message").getAsString();
                String hash_algorithm = e.getOption("hash_algorithm").getAsString().toUpperCase();

                try {
                    MessageDigest messageDigest = MessageDigest.getInstance(hash_algorithm);

                    // Call the Java hashing function, which returns an array of bytes
                    byte[] digestOfMessage = messageDigest.digest(message.getBytes());

                    // Convert the array of bytes to a string.
                    String hashed_message = DatatypeConverter.printBase64Binary(digestOfMessage);

                    reply = "Initial message: `" + message + "`\nHash Algorithm: `"
                            + hash_algorithm + "`\nHashed Message (in base64): ```" + hashed_message + "```";

                } catch (NoSuchAlgorithmException ex) {
                    e.reply("The specified hashing algorithm `" + hash_algorithm + "` is invalid. Try: MD5, SHA-1 or SHA-256").queue();
                }

                if (reply.length() > 2000) { // discord does not allow messages over 2000 characters, so check that here
                    e.reply("Sorry! The output will be too long. Try shortening your input.").queue();
                } else {
                    e.reply(reply).queue(); // reply to the message
                }

                break;
            case "convert": // /convert {type1} {type2} {data}
                String type1 = e.getOption("type1").getAsString(); // to be converted from
                String type2 = e.getOption("type2").getAsString(); // to be converted to
                String data = e.getOption("data").getAsString(); // data to be converted

                if (type1.equalsIgnoreCase("bits")) {
                    reply = convertBits(type2.toLowerCase(), data); // sets the reply to encrypt from bits to type2 using the convertBits method
                } else if (type1.equalsIgnoreCase("string")) {
                    reply = convertString(type2.toLowerCase(), data); // sets the reply to encrypt from string to type2 using the convertString method
                } else if (type1.equalsIgnoreCase("hex")) {
                    reply = convertHex(type2.toLowerCase(), data); // sets the reply to encrypt from hex to type2 using the convertHex method
                } else if (type1.equalsIgnoreCase("base64")) {
                    reply = convertBase64(type2.toLowerCase(), data); // sets the reply to encrypt from base64 to type2 using the convertBase64 method
                } else {
                    e.reply("Incorrect value: \"" + type1 + "\" does not match Bits, String, Hex, or Base64.").queue(); // incorrect input
                }

                if (reply.length() > 2000) { // discord does not allow messages over 2000 characters, so check that here
                    e.reply("Sorry! The output will be too long. Try shortening your input.").queue();
                } else {
                    e.reply("Converted Message: ```" + reply + "```").queue(); // reply to the message
                }

                break;
            case "encrypt": // /encrypt {type} {message} {mode} {key}
                String type = (e.getOption("type").getAsString()); // asymmetric or symmetric
                message = (e.getOption("message").getAsString()); // message to be encrypted
                String mode = "";

                // the following will either get the mode input, or set it to default values
                if (e.getOption("mode") != null) {
                    mode = e.getOption("mode").getAsString(); // sets mode to user input
                } else if (type.equalsIgnoreCase("symmetric")) {
                    mode = "AES-128"; // sets mode to AES-128 if no user input and type is symmetric
                } else if (type.equalsIgnoreCase("asymmetric")) {
                    mode = "RSA"; // sets mode to RSA if no user input and type is asymmetric
                }

                SecretKey key;
                boolean found = false;

                mode = mode.replaceAll("AES-", ""); // ensures mode only includes the bit level, since only AES is supported
                String[] validModesSymmetricArray = {"128", "192", "256"}; // valid modes for symmetric
                String[] validModesAsymmetricArray = {"RSA"}; // valid modes for asymmetric
                List<String> validModesSymmetric = Arrays.asList(validModesSymmetricArray); // convert to list
                List<String> validModesAsymmetric = Arrays.asList(validModesAsymmetricArray); // convert to list

                if (type.equalsIgnoreCase("symmetric")) {
                    try {
                        if (!validModesSymmetric.contains(mode)) { // mode validation for symmetric
                            reply = "Your specified mode of `" + mode + "` is not a valid mode for asymmetric encryption. Valid modes include: AES-128, AES-196, and AES-256";
                        } else if (e.getOption("key") != null) { // a key was provided by user
                            byte[] inputKeyBytes = e.getOption("key").getAsString().getBytes(); // converts user input key
                            key = new SecretKeySpec(inputKeyBytes, 0, inputKeyBytes.length, "AES"); // gets the key
                            reply = "Your encrypted message is: ```" + encryptMessageSymmetric(key, message) + "```"; // reply message
                        } else { // auto generates get if none provided
                            key = generateSymmetricKey(Integer.parseInt(mode)); // generates key
                            String keyString = DatatypeConverter.printBase64Binary(key.getEncoded()); //gets string of key to return to user
                            reply = "Your encrypted message is: ```" + encryptMessageSymmetric(key, message) + "```\n\nYour secret key is: ```" + keyString + "```"; //reply message
                        }
                    } catch (GeneralSecurityException ex) {
                        reply = "An error occurred. Maybe you put in an invalid key."; // catch message; this should only happen if the key input was invalid
                    }
                } else if (type.equalsIgnoreCase("asymmetric")) {
                    try {
                        if (message.getBytes().length > 117) { // message validation; methods can't support over 117 bytes
                            reply = "Sorry! Your message was too long. We can only support up to 117 bytes of information for asymmetric encryption.\n" +
                                    "Your input included `" + message.getBytes().length + "` of information. Try shortening your message.";
                        } else if (!validModesAsymmetric.contains(mode)) { // mode validation for asymmetric
                            reply = "Your specified mode of `" + mode + "` is not a valid mode for asymmetric encryption. Valid modes include: RSA";
                        } else if (e.getOption("key") == null) { // checks if a user hasn't provided a key

                            // the following will try to see if a user has an associated private key with their discord id. if they do, that will be used by default
                            found = false;
                            for (int i = 0; i < userKeys.size(); i++) {
                                if (userKeys.get(i).getUser().equals(e.getUser().getId())) {
                                    reply = "Your encrypted message is: ```" + userKeys.get(i).encryptMessageAsymmetric(message) + "```";
                                    found = true;
                                }
                            }

                            // if there is no private key associated with their discord id, a key pair will be generated for them
                            if (!found) {
                                KeyPair keyPair = generateAsymmetricKeys();
                                PrivateKey privateKey = keyPair.getPrivate();
                                PublicKey publicKey = keyPair.getPublic();
                                userKeys.add(new UserKey(e.getUser().getId(), privateKey, publicKey));

                                String privateKeyString = DatatypeConverter.printBase64Binary(privateKey.getEncoded());
                                e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("Your private key is: ```" + privateKeyString + "```")).queue();

                                String publicKeyString = DatatypeConverter.printBase64Binary(publicKey.getEncoded());
                                reply = "Your encrypted message is: ```" + UserKey.encryptMessageAsymmetric(publicKey, message) + "```\n\nThe public key used to encrypt this is: ```" + publicKeyString + "```";
                            }

                        } else {
                            // if a key has been provided, it is decoded and used to decrypt the message
                            byte[] publicKeyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            PublicKey publicKey = keyFactory.generatePublic(keySpec);

                            reply = "Your encrypted message is: ```" + UserKey.encryptMessageAsymmetric(publicKey, message) + "```";
                        }
                    } catch (GeneralSecurityException ex) {
                        reply = "An error occurred. Your private key cannot decrypt this message."; // error handling should occur if the user's key can't decrypt the message
                    }
                } else {
                    reply = "The specified type of `" + type + "` does not match \"symmetric\" or \"asymmetric\""; // type validation
                }

                if (reply.length() > 2000) { // discord does not allow messages over 2000 characters, so check that here
                    e.reply("Sorry! The output will be too long. Try shortening your input.").queue();
                } else {
                    e.reply(reply).queue(); // reply message
                }

                break;
            case "decrypt": // /decrypt {message} {type} {key}
                message = e.getOption("message").getAsString(); // cipher text to be decrypted
                type = (e.getOption("type").getAsString()); // asymmetric or symmetric

                if (type.equalsIgnoreCase("symmetric")) {
                    try {
                        if (e.getOption("key") != null) {  // decodes and uses the provided key for symmetric decryption
                            byte[] keyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                            key = new SecretKeySpec(keyBytes, "AES");
                            reply = "Your decrypted message is: ||```" + decryptMessageSymmetric(key, message) + "```||";
                        } else { // ensures a key is provided for symmetric decryption
                            reply = "You will need to specify a key for symmetric decryption. Add \"key:KEY\" to your command";
                        }
                    } catch (GeneralSecurityException ex) {
                        reply = "An error occurred. Either you entered an invalid key, or your key doesn't decrypt this message."; // error handling if key can't decrypt message
                    }
                } else if (type.equalsIgnoreCase("asymmetric")) {
                    if (e.getOption("key") == null) {
                        // tries to use a private key associated with discord id to decrypt message
                        found = false;
                        for (int i = 0; i < userKeys.size(); i++) {
                            if (userKeys.get(i).getUser().equals(e.getUser().getId())) {
                                found = true;
                                try {
                                    reply = "Your decrypted message is: ||```" + userKeys.get(i).decryptMessageAsymmetric(message) + "```||";
                                } catch (GeneralSecurityException ex) {
                                    reply = "An error occurred. The private key associated with your ID doesn't decrypt this message.";
                                }
                            }
                        }

                        // if no key pair for the user was found, let them know to generate keys
                        if (!found) {
                            reply = "You do not have a private key associated with your ID! Try `/generate_keys` to get a key, or add a private key to this message to decrypt with.";
                        }

                    } else {
                        try {
                            // decode the inputted key and use it to decrypt
                            byte[] privateKeyBytes = Base64.getDecoder().decode(e.getOption("key").getAsString());
                            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

                            reply = "Your decrypted message is: ||```" + UserKey.decryptMessageAsymmetric(privateKey, message) + "```||";
                        } catch (GeneralSecurityException ex) { // error handling if the key doesn't work
                            reply = "An error occurred. Either you entered an invalid key, or your key doesn't decrypt this message.";
                        }
                    }
                } else {
                    reply = "The specified type of `" + type + "` does not match \"symmetric\" or \"asymmetric\"";
                }

                if (reply.length() > 2000) { // discord does not allow messages over 2000 characters, so check that here
                    e.reply("Sorry! The output will be too long. Try shortening your input.").queue();
                } else {
                    e.reply(reply).queue(); // reply message
                }

                break;
            case "message": // /message {message} {user}
                message = e.getOption("message").getAsString(); // message content
                String user = e.getOption("user").getAsString(); // user intended to receive message
                String userParsed = user.replaceAll("<@", "").replaceAll(">", ""); // just discord id of the user, removes @
                String cipher = "";

                try {
                    // tries to find the public key of the receiver and encrypt the message
                    found = false;
                    for (int i = 0; i < userKeys.size(); i++) {
                        if (userKeys.get(i).getUser().equals(userParsed)) {
                            cipher = userKeys.get(i).encryptMessageAsymmetric(message);
                            found = true;
                        }
                    }

                    if (found) {
                        Message msg = new Message("<@" + e.getUser().getId() + ">", user, cipher); // create a message instance
                        reply = msg.getReceiver() + " you were just sent a message from " + msg.getSender() + "\nThe cipher text is: " + msg.getCipher() +
                                "\n\nYou can use the /decrypt command to decrypt the cipher with your private key, or use the following command:\n`/decrypt_message " + msg.getId() + "`";
                        if (reply.length() > 2000) { // discord does not allow messages over 2000 characters, so check that here
                            e.reply("Sorry! The output will be too long. Try shortening your input.").queue();
                        } else {
                            messages.add(msg); // adds the message instance to the messages list to keep track of it
                            e.reply(reply).queue();
                        }
                    } else { // no public key found for the receiver
                        e.reply("The receiver does not have a pair of keys generated. Please let them know to run the command `/generate_keys`").queue();
                    }
                } catch (GeneralSecurityException ex) { // exception handling if the message was too long to encrypt
                    e.reply("An error occurred! Maybe your message was too long.").queue();
                }
                break;
            case "decrypt_message": // /decrypt_message {id}
                String id = e.getOption("id").getAsString(); // id of the message
                String userId = "<@" + e.getUser().getId() + ">"; // userId as it would be stored in the message instance
                found = false;

                if (!id.matches("\\d+") || (Integer.parseInt(id) < 1 || Integer.parseInt(id) > messages.size())) { // validates id input
                    e.reply("Invalid ID!").queue();
                    found = true;
                } else {
                    Integer idInt = Integer.valueOf(id);
                    Message selectedMessage = messages.get(idInt - 1); // gets the message instance of id
                    // the following will find the private key associated with the user and attempt to decrypt the message
                    for (int i = 0; i < userKeys.size(); i++) {
                        if (userKeys.get(i).getUser().equals(e.getUser().getId())) {
                            found = true;
                            try {
                                e.reply("The decrypted message is:\n||```" + userKeys.get(i).decryptMessageAsymmetric(selectedMessage.getCipher()) + "```||").queue();
                            } catch (
                                    GeneralSecurityException ex) { // error handling if the user's private key can't decrypt the message
                                e.reply("The private key on your ID doesn't work for this message! Either you are not the intended " +
                                        "user for this message, or maybe you regenerated keys.").queue();
                            }
                            break;
                        }
                    }
                }
                if (!found) { // reply if no private key was found for the user's profile
                    e.reply("No keys could be found from your profile!").queue();
                }
                break;
            case "generate_keys": // /generate_keys
                userId = e.getUser().getId(); // discord ID to associate with key pair
                int spot = 0; // index of user if they already have a keypair
                found = false;
                try {
                    for (int i = 0; i < userKeys.size(); i++) { // finds if the user already has a key pair
                        if (userKeys.get(i).getUser().equals(userId)) {
                            spot = i;
                            found = true;
                        }
                    }
                    KeyPair keyPair = generateAsymmetricKeys(); // generates key pair
                    String publicKey = new String(Base64.getEncoder().encode(keyPair.getPublic().getEncoded())); // gets string of public key
                    String privateKey = new String(Base64.getEncoder().encode(keyPair.getPrivate().getEncoded())); // gets string of private key
                    if (found) { // resets the public and private key of an existing user
                        userKeys.get(spot).setPrivateKey(keyPair.getPrivate());
                        userKeys.get(spot).setPublicKey(keyPair.getPublic());
                        e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("Your old public and private keys are no longer associated with your ID." +
                                " The new private key is: ```" + privateKey + "```")).queue();
                    } else { // creates a new instance in userKeys for the user
                        UserKey userKey = new UserKey(userId, keyPair.getPrivate(), keyPair.getPublic());
                        e.getUser().openPrivateChannel().flatMap(channel -> channel.sendMessage("Your private key is: ```" + privateKey + "```")).queue();
                        userKeys.add(userKey);
                    }
                    e.reply("Your private key has been DM'd to you.\nYour public key is: ```" + publicKey + "```").queue();
                } catch (NoSuchAlgorithmException ex) { // generic error handling incase something goes wrong
                    e.reply("An error occurred! Sorry!").queue();
                }
                break;
            case "get_public_key": // /get_public_key {user}
                userId = e.getOption("user").getAsString().replaceAll("<@", "").replaceAll(">", ""); // parses user input

                // loop through userKeys and attempt to find the public key of the specified user
                found = false;
                for (int i = 0; i < userKeys.size(); i++) {
                    if (userKeys.get(i).getUser().equals(userId)) {
                        reply = "This user's public key is: " + userKeys.get(i).getPublicKey();
                        found = true;
                    }
                }

                if (!found) { // response if the user was not found
                    reply = "Either this user doesn't exist, or they don't have an associated key pair. The user can generate a key pair with `/generate_keys`";
                }

                e.reply(reply).queue();
                break;
        }
    }

    /**
     * Convert bits to a specified encoding method.
     *
     * @param type Type of encoding method to encode to
     * @param data Data to be encoded
     * @return The output of the conversion
     */
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

    /**
     * Convert string to a specified encoding method.
     *
     * @param type Type of encoding method to encode to
     * @param data Data to be encoded
     * @return The output of the conversion
     */
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

    /**
     * Convert hex to a specified encoding method.
     *
     * @param type Type of encoding method to encode to
     * @param data Data to be encoded
     * @return The output of the conversion
     */
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

    /**
     * Convert base64 to a specified encoding method.
     *
     * @param type Type of encoding method to encode to
     * @param data Data to be encoded
     * @return The output of the conversion
     */
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

    /**
     * Convert bits to a string.
     *
     * @param bits Bits to be converted
     * @return The converted string
     */
    public String bitsToString(String bits) {
        bits = bits.replaceAll(" ", "");
        byte[] bytes = new byte[bits.length() / 8];

        for (int i = 0; i < bits.length() - 7; i += 8) {
            bytes[i / 8] = (byte) Integer.parseInt(bits.substring(i, i + 8), 2);
        }

        String str = new String(bytes, StandardCharsets.UTF_8);
        return str;
    }

    /**
     * Convert string to bits.
     *
     * @param str String to be converted
     * @return The bits in the form of a string
     */
    public String stringToBits(String str) {
        String bits = "";
        String value = "";

        for (int i = 0; i < str.length(); i++) {
            value = String.format("%8s", Integer.toBinaryString(str.charAt(i))).replaceAll(" ", "0");
            bits += value + " ";
        }

        return bits;
    }

    /**
     * Convert hex to a string.
     *
     * @param hex Bits to be converted
     * @return The converted string
     */
    public String hexToString(String hex) {
        return new String(DatatypeConverter.parseHexBinary(hex));
    }

    /**
     * Convert string to hex.
     *
     * @param str String to be converted
     * @return The hex in the form of a string
     */
    public String stringToHex(String str) {
        byte[] bytes = str.getBytes();
        return DatatypeConverter.printHexBinary(bytes);
    }

    /**
     * Convert base64 to a string.
     *
     * @param base64 Bits to be converted
     * @return The converted string
     */
    public String base64ToString(String base64) {
        return new String(DatatypeConverter.parseBase64Binary(base64));
    }

    /**
     * Convert string to base64.
     *
     * @param str String to be converted
     * @return The base64 in the form of a string
     */
    public String stringToBase64(String str) {
        byte[] bytes = str.getBytes();
        return DatatypeConverter.printBase64Binary(bytes);
    }

    /**
     * Generate a secret key for symmetric encryption.
     *
     * @param aes The bit level for the AES key
     * @return The generated secret key
     */
    public SecretKey generateSymmetricKey(int aes) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(aes);
        SecretKey key = generator.generateKey();
        return key;
    }

    /**
     * Encrypt a message using symmetric encryption.
     *
     * @param secretKey The key to use in encryption
     * @param message   The message to encrypt
     * @return The ciphertext
     */
    public String encryptMessageSymmetric(SecretKey secretKey, String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypt a message using symmetric encryption.
     *
     * @param secretKey The key to use in decryption
     * @param message   The ciphertext to decrypt
     * @return The plaintext
     */
    public static String decryptMessageSymmetric(SecretKey secretKey, String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException {
        byte[] encryptedBytes = Base64.getDecoder().decode(message);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes);
    }

    /**
     * Generate a key pair for asymmetric encryption.
     *
     * @return The generated key pair
     */
    public static KeyPair generateAsymmetricKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.genKeyPair();
        return keyPair;
    }
}