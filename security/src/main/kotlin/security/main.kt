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
     */

    val InitialDHOutputA = DiffieHellman(Alice.DHKeyPair.second, Bob.DHKeyPair.first)
    val SKROutputs = Alice.SymmetricKeyRatchetRoot(InitialDHOutputA)
    Alice.sendingKey = SKROutputs

    /*
        SITUATION 2: Alice sends message
     */

    val SKRSending = Alice.SymmetricKeyRatchetNonRoot(true)
    val A1 = SKRSending

    val AliceMessage1 = Message(Alice.DHKeyPair.first.encoded, A1)

    /*
        SITUATION 3: Bob receives message
     */

    val DHOutputsB = Bob.DiffieHellmanRatchet(Alice.DHKeyPair.first.encoded)
    val SKROutputsBR = Bob.SymmetricKeyRatchetRoot(DHOutputsB?.first!!)
    Bob.receivingKey = SKROutputsBR
    val SKROutputsBS = Bob.SymmetricKeyRatchetRoot(DHOutputsB.second)
    Bob.sendingKey = SKROutputsBS

    // Getting receivingKey

    val SKRReceiving = Bob.SymmetricKeyRatchetNonRoot(false)
    val A1Decrypt = SKRReceiving

    val bobToBeDecrypted1 = Message(Bob.DHKeyPair.first.encoded, A1Decrypt)

    val b = 2


    /*
        Bob sends message B1 + B2
     */

    // Bob creates and sends messages

    val B1 = Bob.SymmetricKeyRatchetNonRoot(true)
    val e = Bob.sendingKey
    val messageB1 = Message(Bob.DHKeyPair.first.encoded, Bob.sendingKey!!)
    val B2 = Bob.SymmetricKeyRatchetNonRoot(true)
    val messageB2 = Message(Bob.DHKeyPair.first.encoded, B2)

    // Alice receives message


    if (messageB1.publicKey == Alice.prevPublicKey) {
        throw RuntimeException("Public keys hould not be the same !!!")
    }

    val DHOutputsB12 = Alice.DiffieHellmanRatchet(messageB1.publicKey)
    Alice.receivingKey = Alice.SymmetricKeyRatchetRoot(DHOutputsB12!!.first)
    Alice.sendingKey = Alice.SymmetricKeyRatchetRoot(DHOutputsB12.second)
    val B1Decrypt = Alice.SymmetricKeyRatchetNonRoot(false)

    val messageB1Decrypt = Message(Bob.DHKeyPair.first.encoded, B1Decrypt)

    val B2Decrypt = Alice.SymmetricKeyRatchetNonRoot(false)
    val messageB2Decrypt = Message(Bob.DHKeyPair.first.encoded, B2Decrypt)

    val c = 2

}

data class Message(
    val publicKey: ByteArray,
    val encryptionKey: ByteArray
)