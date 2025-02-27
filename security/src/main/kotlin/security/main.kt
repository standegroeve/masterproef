package security

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters

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

     uploadPreKeys(Bob.podId, Bob.preKeys!!.getPublic())

    /*
        STEP 2: Send the Initial Message
        (From Alice)
     */

    Alice.sharedKey = sendInitialMessage(Alice, Bob.podId, Bob.preKeys!!.privateIdentityPreKey, Alice.preKeys!!)

    /*
        STEP 3: Process the Initial Message
        (From Bob)
     */

    Bob.sharedKey = processInitialMessage(Bob, Bob.podId, Bob.preKeys!!)

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

    val messageA1 = Alice.sendInitialMessage()


    /*
        SITUATION 3: Bob receives message
     */


    val messageA1Decrypted = Bob.receiveMessage(messageA1.publicKey)

    val b = 2


    /*
        Bob sends message B1 + B2
     */

    // Bob creates and sends messages

    val messageB1 = Bob.sendMessage()
    val messageB2 = Bob.sendMessage()

    // Alice receives message

    val messageB1Decrypt = Alice.receiveMessage(messageB1.publicKey)
    val messageB2Decrypt = Alice.receiveMessage(messageB2.publicKey)

    val c = 2

}