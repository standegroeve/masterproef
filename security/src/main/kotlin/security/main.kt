package security

import security.crypto.generatePrekeys

fun main() {

    // this is the pod where the messages will be send to
    val targetPodId = "bob"

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

     X3DH.uploadPreKeys(targetPodId, Bob.preKeys!!.getPublic())

    /*
        STEP 2: Send the Initial Message
        (From Alice)
     */

    Alice.sharedKey = X3DH.sendInitialMessage(Alice, targetPodId, Alice.preKeys!!)

    /*
        STEP 3: Process the Initial Message
        (From Bob)
     */

    Bob.sharedKey = X3DH.processInitialMessage(Bob, targetPodId, Bob.preKeys!!)

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

    Alice.sendInitialMessage(targetPodId, "initialMessage".toByteArray())

    /*
        SITUATION 3: Bob receives message
     */


    val messageA1Decrypt = Bob.receiveMessage(targetPodId)
    val string = messageA1Decrypt[0].plainText

    val b = 2


    /*
        Bob sends message B1 + B2
     */

    // Bob creates and sends messages

    Bob.sendMessage(targetPodId, "test_sending_message".toByteArray())
    Bob.sendMessage(targetPodId, "test2".toByteArray())

    // Alice receives message

    val messageB12Decrypt = Alice.receiveMessage(targetPodId)



    val c = 2

    /*
        Alice sends A2
     */

    Alice.sendMessage(targetPodId, "testA2".toByteArray())
    val messageA2Decrypt = Bob.receiveMessage(targetPodId)


    /*
        Bob sends message B3 + B4 + B5
     */

    // Bob creates and sends messages

    Bob.sendMessage(targetPodId, "test3".toByteArray())
    Bob.sendMessage(targetPodId, "test4".toByteArray())
    Bob.sendMessage(targetPodId, "test5".toByteArray())

    // Alice receives message

    val messageB345Decrypt = Alice.receiveMessage(targetPodId)

    val d = 2

}