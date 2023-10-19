package org.example;

import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.hooks.ListenerAdapter;

public class CryptoBot extends ListenerAdapter {
    @Override
    public void onSlashCommandInteraction(SlashCommandInteractionEvent e) {
//                if(e.getName().equals("hi")){
//                    e.reply("hi ;)").queue();
//                }

        e.deferReply();

        try {
            switch (e.getName()) {
                case "hi":
                    e.reply("hi ;)").queue();
                    break;

                case "hash":
                    String hashedString;
                    String hashFunc = e.getOption("hash_func").getAsString();
                    // TODO add in the actual hash function later!∂

                    switch(hashFunc) {
                        case "sha256":
                            hashedString = "sha256:";
                            break;
                        case "sha512":
                            hashedString = "sha512:";
                            break;
                        default:
                            throw new IllegalArgumentException("Invalid hash function input: '" + hashFunc + "'");
                    }

                    hashedString += e.getOption("input_string").getAsString();

                    if (e.getOption("hash_func") == null || e.getOption("hash_func") == null)
                        throw new NullPointerException("You must provide all inputs to the command!");

                    e.reply("Hash: " + hashedString).queue();
                    break;

            }
        } catch (NullPointerException | IllegalArgumentException exception) {
            e.reply(exception.getMessage());
        }
    }
}