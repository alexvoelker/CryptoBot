package org.example;

public class Message {

    static int count;
    Integer id;
    String sender;
    String receiver;
    String cipher;
    public Message(String sender, String receiver, String cipher){
        count++;
        id = count;
        this.sender = sender;
        this.receiver = receiver;
        this.cipher = cipher;
    }

    public Integer getId(){
        return id;
    }

    public String getSender(){
        return sender;
    }

    public String getReceiver(){
        return receiver;
    }

    public String getCipher() { return cipher; }
}
