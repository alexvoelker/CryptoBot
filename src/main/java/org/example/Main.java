package org.example;

import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.entities.Activity;
import net.dv8tion.jda.api.entities.Guild;
import net.dv8tion.jda.api.interactions.commands.OptionType;
import net.dv8tion.jda.api.interactions.commands.build.Commands;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

/**
 * @author Group 2
 */

public class Main {

    public static void main(String[] args) throws FileNotFoundException, InterruptedException {
        // Read in the bot key from the file "BOT_KEY" in the project root directory ("CryptoBot/")
        // Note that you need to add this file in the .gitignore
        Scanner keyReader = new Scanner(new File("BOT_KEY"));
        String TOKEN = keyReader.nextLine();


        JDABuilder jdaBuilder = JDABuilder.createDefault(TOKEN);
        JDA jda = jdaBuilder.setActivity((Activity.watching("you"))).addEventListeners(new CryptoBot()).build();
        jda.awaitReady();

        Guild guild = jda.getGuildById("1157522711715790858");

        if (guild != null) {
            guild.updateCommands()
                    .addCommands(Commands.slash("hi", "testing"))
                    .addCommands(Commands.slash("hash", "find the hash of an input")
                            .addOption(OptionType.STRING, "hash_func", "The hash function (sha256, sha512)")
                            .addOption(OptionType.STRING, "input_string", "The text to be hashed"))
                    .queue();
        }

    }
}