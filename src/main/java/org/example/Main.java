package org.example;

import net.dv8tion.jda.api.JDA;
import net.dv8tion.jda.api.JDABuilder;
import net.dv8tion.jda.api.entities.Activity;
import net.dv8tion.jda.api.entities.Guild;

/**
 * @author Group 6
 */

public class Main {

    public static void main(String[] args) throws InterruptedException {
        JDABuilder jdaBuilder = JDABuilder.createDefault("MTE2MzkzNTUzNTc4MjQ0MTA2MA.GmXHj8.JyXXTZvCJzOYt3K8sFQdsfFH1LfQWV8Hq0T5GA");
        JDA jda = jdaBuilder.setActivity((Activity.watching("you"))).addEventListeners(new Commands()).build().awaitReady();

        Guild guild = jda.getGuildById("1157522711715790858");

        if (guild != null){
            guild.upsertCommand("hi", "testing").queue();
        }

    }
}