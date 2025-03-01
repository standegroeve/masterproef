package security

import security.crypto.generatePrekeys

fun main() {
    /*


        START X3DH


     */


    // Bob want to enable Alice to get access to its pod
    // So they can exchange messages via this pod

    /*
        Step 0: Generate Prekeys
     */

    val Alice = User("alice")
    val Bob = User("bob")
    Alice.preKeys = generatePrekeys()
    Bob.preKeys = generatePrekeys()

    /*
        STEP 1: Place Keys on Server
        (From Bob)
     */

     X3DH.uploadPreKeys(Bob.podId, Bob.preKeys!!.getPublic())

    /*
        STEP 2: Send the Initial Message
        (From Alice)
     */

    Alice.sharedKey = X3DH.sendInitialMessage(Alice, Bob.podId, Bob.preKeys!!.privateIdentityPreKey, Alice.preKeys!!)

    /*
        STEP 3: Process the Initial Message
        (From Bob)
     */

    Bob.sharedKey = X3DH.processInitialMessage(Bob, Bob.podId, Bob.preKeys!!)

    val a = 2


    /*

        X3DH FINISHED
        START DOUBLE RATCHET ALGORITHM

     */

    /*
        TODO: make inboxes or message system
     */

//    // Inbox Alice
//    val inboxAlice = emptyList<Message>()
//    // Inbox Bob
//    val inboxBob = emptyList<Message>()

    /*
        SITUATION 1: Initialisation of Alice
                    +
        SITUATION 2: Alice sends message
     */

    val messageA1 = Alice.sendInitialMessage("initialMessage".toByteArray())

    /*
        SITUATION 3: Bob receives message
     */


    val messageA1Decrypt = Bob.receiveMessage(messageA1, messageA1.publicKey)
    val string = messageA1Decrypt.plainText

    val b = 2


    /*
        Bob sends message B1 + B2
     */

    // Bob creates and sends messages

    val messageB1 = Bob.sendMessage("test_sending_message".toByteArray())
    val messageB2 = Bob.sendMessage("test2".toByteArray())

    // Alice receives message

    val messageB1Decrypt = Alice.receiveMessage(messageB1, messageB1.publicKey)
    val messageB2Decrypt = Alice.receiveMessage(messageB2, messageB2.publicKey)

    val string1 = messageB1Decrypt.plainText
    val string2 = messageB2Decrypt.plainText

    val c = 2

    /*
        Alice sends A2
     */

    val messageA2 = Alice.sendMessage("testA2".toByteArray())
    val messageA2Decrypt = Bob.receiveMessage(messageA2, messageA2.publicKey)
    val stringA2 = messageA2Decrypt.plainText

    /*
        Bob sends message B3 + B4 + B5
     */

    // Bob creates and sends messages

    val messageB3 = Bob.sendMessage("test3".toByteArray())
    val messageB4 = Bob.sendMessage("test4".toByteArray())
    val messageB5 = Bob.sendMessage("test5".toByteArray())

    // Alice receives message

    val messageB3Decrypt = Alice.receiveMessage(messageB3, messageB3.publicKey)
    val messageB4Decrypt = Alice.receiveMessage(messageB4, messageB4.publicKey)
    val messageB5Decrypt = Alice.receiveMessage(messageB5, messageB5.publicKey)


    val string3 = messageB3Decrypt.plainText
    val string4 = messageB4Decrypt.plainText
    val string5 = messageB5Decrypt.plainText

    val d = 2

}