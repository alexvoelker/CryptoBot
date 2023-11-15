package org.example;

public class Message {

    static int count;
    String id;
    String sender;
    String receiver;
    String cipher;
    public Message(String sender, String receiver, String cipher){
        count++;
        id = String.valueOf(count);
        this.sender = sender;
        this.receiver = receiver;
        this.cipher = cipher;
    }

    public String getId(){
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
