package org.example;

public class Message {

    static int count;
    Integer id;
    String sender;
    String receiver;
    String cipher;

    /**
     * Constructor for Message keep track of message ciphertexts with their sender and intended receiver
     *
     * @param sender The discord ID of the sender with <@ prefix and > suffix
     * @param receiver The discord ID of the receiver with <@ prefix and > suffix
     * @param cipher The cipher text of the message
     */
    public Message(String sender, String receiver, String cipher){
        count++;
        id = count;
        this.sender = sender;
        this.receiver = receiver;
        this.cipher = cipher;
    }

    /**
     * Get the ID of the message.
     *
     * @return The ID of the message
     */
    public Integer getId(){
        return id;
    }

    /**
     * Get the ID of the sender.
     *
     * @return The ID of the sender
     */
    public String getSender(){
        return sender;
    }

    /**
     * Get the ID of the receiver.
     *
     * @return The ID of the receiver
     */
    public String getReceiver(){
        return receiver;
    }

    /**
     * Get the ciphertext.
     *
     * @return The ciphertext
     */
    public String getCipher() { return cipher; }
}
