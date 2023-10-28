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
        // Note that you need to add this file in as it's included in the .gitignore
        Scanner keyReader = new Scanner(new File("BOT_KEY"));
        String TOKEN = keyReader.nextLine();

        JDABuilder jdaBuilder = JDABuilder.createDefault(TOKEN);
        JDA jda = jdaBuilder.setActivity((Activity.watching("you"))).addEventListeners(new Commands()).build().awaitReady();
        jda.awaitReady();

        Guild guild = jda.getGuildById("1157522711715790858");

        if (guild != null){
            guild.upsertCommand("hi", "testing").queue();
            guild.upsertCommand("s2b", "String to Base64").addOption(OptionType.STRING,"string", "String to be converted", true).queue();
            guild.upsertCommand("b2s", "Base64 to String").addOption(OptionType.STRING,"base64", "Base64 to be converted", true).queue();
            guild.upsertCommand("s2h", "String to Hex").addOption(OptionType.STRING,"string", "String to be converted", true).queue();
            guild.upsertCommand("h2s", "Hexadecimal to String").addOption(OptionType.STRING,"hex", "Hexadecimal to be converted", true).queue();
            guild.upsertCommand("s2bits", "String to Bits").addOption(OptionType.STRING,"string", "String to be converted", true).queue();
            guild.upsertCommand("bits2s", "Bits to UTF-8 String").addOption(OptionType.STRING,"bits", "Bits to be converted", true).queue();
            guild.upsertCommand("create", "Create a message").addOption(OptionType.STRING,"msg", "Message", true).queue();
            guild.upsertCommand("encrypt", "Encrypt a message").addOption(OptionType.STRING,"id", "ID of Message", true).queue();
            guild.upsertCommand("decrypt", "Decrypt a message").addOption(OptionType.STRING,"id", "ID of Message", true).queue();
        }
    }
}