package org.example;

import net.dv8tion.jda.api.events.interaction.command.SlashCommandInteractionEvent;
import net.dv8tion.jda.api.hooks.ListenerAdapter;
import net.dv8tion.jda.api.interactions.commands.OptionMapping;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;

public class Commands extends ListenerAdapter {
    ArrayList<Message> messages = new ArrayList<Message>();
    @Override
    public void onSlashCommandInteraction(SlashCommandInteractionEvent e) {
        if(e.getName().equals("hi")){
            e.reply("hi").queue();
        }
        if(e.getName().equals("s2b")){
            OptionMapping messageOption = e.getOption("string");
            byte[] bytes = messageOption.getAsString().getBytes();
            e.reply(DatatypeConverter.printBase64Binary(bytes)).queue();
        }
        if(e.getName().equals("b2s")){
            OptionMapping messageOption = e.getOption("base64");
            String reply = new String(DatatypeConverter.parseBase64Binary(messageOption.getAsString()));
            e.reply(reply).queue();
        }
        if(e.getName().equals("s2h")){
            OptionMapping messageOption = e.getOption("string");
            byte[] bytes = messageOption.getAsString().getBytes();
            e.reply(DatatypeConverter.printHexBinary(bytes)).queue();
        }
        if(e.getName().equals("h2s")){
            OptionMapping messageOption = e.getOption("hex");
            String reply = new String(DatatypeConverter.parseHexBinary(messageOption.getAsString()));
            e.reply(reply).queue();
        }
        if(e.getName().equals("s2bits")){
            OptionMapping messageOption = e.getOption("string");
            String str = messageOption.getAsString();
            String bits = "";
            String value = "";
            for(int i = 0; i < str.length(); i++){
                value = String.format("%8s", Integer.toBinaryString(str.charAt(i))).replaceAll(" ", "0");
                bits += value + " ";
            }
            e.reply(bits).queue();
        }
        if(e.getName().equals("bits2s")){
            OptionMapping messageOption = e.getOption("bits");
            String bits = messageOption.getAsString().replaceAll(" ", "");
            byte[] bytes = new byte[bits.length() / 8];
            for(int i = 0; i < bits.length()-7; i+=8){
                bytes[i/8] = (byte) Integer.parseInt(bits.substring(i,i+8),2);
            }
            String str = new String(bytes, StandardCharsets.UTF_8);
            e.reply(str).queue();
        }
        if(e.getName().equals("create")){
            OptionMapping messageOption = e.getOption("msg");
            Message message = new Message(messageOption.getAsString());
            messages.add(message);
            e.reply("Your message ID is: " + message.getId()).queue();
        }
        if(e.getName().equals("encrypt")){
            OptionMapping messageOption = e.getOption("id");
            String id = messageOption.getAsString();
            Message message = null;
            for(int i = 0; i < messages.size(); i++){
                if(messages.get(i).getId().equals(id)){
                    message = messages.get(i);
                }
            }
            if(message == null) {
                e.reply("Message with ID of \"" + id + "\" cannot be found.").queue();
            } else {
                try {
                    e.reply("Your encrypted message is: " + message.encryptMessage()).queue();
                } catch (GeneralSecurityException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
        if(e.getName().equals("decrypt")){
            OptionMapping messageOption = e.getOption("id");
            String id = messageOption.getAsString();
            Message message = null;
            for(int i = 0; i < messages.size(); i++){
                if(messages.get(i).getId().equals(id)){
                    message = messages.get(i);
                }
            }
            if(message == null) {
                e.reply("Message with ID of \"" + id + "\" cannot be found.").queue();
            } else {
                try {
                    e.reply("Your decrypted message is: " + message.decryptMessage()).queue();
                } catch (GeneralSecurityException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }
    }
}