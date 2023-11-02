package org.example;

import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.entities.Activity;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Scanner;

/**
 * @author Group 2
 */

public class Main {
    static JDA jda;
    public static void main(String[] args) throws InterruptedException, FileNotFoundException {
        // Read in the bot key from the file "BOT_KEY" in the project root directory ("CryptoBot/")
        Scanner keyReader = new Scanner(new File("BOT_KEY"));
        String TOKEN = keyReader.nextLine();

        JDABuilder jdaBuilder = JDABuilder.createDefault(TOKEN);
        jda = jdaBuilder.setActivity((Activity.watching("you"))).addEventListeners(new BotCommands()).build().awaitReady();
        jda.awaitReady();
    }

    public static JDA getJDA(){
        return jda;
    }
}