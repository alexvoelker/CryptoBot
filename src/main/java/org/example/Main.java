package org.example;

import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.entities.Activity;
import net.dv8tion.jda.api.entities.Guild;
import net.dv8tion.jda.api.interactions.commands.OptionType;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

/**
 * @author Group 2
 */

public class Main {
    public static void main(String[] args) throws InterruptedException, FileNotFoundException {
        // Read in the bot key from the file "BOT_KEY" in the project root directory ("CryptoBot/")
        Scanner keyReader = new Scanner(new File("BOT_KEY"));
        String TOKEN = keyReader.nextLine();

        JDABuilder jdaBuilder = JDABuilder.createDefault(TOKEN);
        JDA jda = jdaBuilder.setActivity((Activity.watching("you"))).addEventListeners(new Commands()).build().awaitReady();
        jda.awaitReady();

        Guild guild = jda.getGuildById("1157522711715790858");

        if (guild != null){
            //testing command
            guild.upsertCommand("hi", "testing").queue();

            //datatype conversions
            guild.upsertCommand("convert", "Convert data from Type1 to Type2")
                    .addOption(OptionType.STRING,"type1", "Input data type", true)
                    .addOption(OptionType.STRING,"type2", "Output data type", true)
                    .addOption(OptionType.STRING,"data", "Data to be converted", true).queue();

            //AES symmetric key encryption
            guild.upsertCommand("encrypt", "Encrypt a message")
                    .addOption(OptionType.STRING,"message", "Message to be encrypted", true)
                    .addOption(OptionType.STRING,"aes", "Mode of encryption: AES-128, AES-192, AES-256", true)
                    .addOption(OptionType.STRING,"key", "Private Key for encryption (auto generated if none provided)", false).queue();
            guild.upsertCommand("decrypt", "Decrypt a message")
                    .addOption(OptionType.STRING,"message", "Message to be decrypted", true)
                    .addOption(OptionType.STRING,"key", "Private Key for decryption", true).queue();;
        }
    }
}