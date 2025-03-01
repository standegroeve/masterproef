import org.junit.jupiter.api.Test
import security.*
import security.crypto.generatePrekeys


class securityTests() {

    @Test
    fun X3DHTest() {
        // STEP 0: Generate Prekeys
        val Alice = User("alice")
        val Bob = User("bob")
        Alice.preKeys = generatePrekeys()
        Bob.preKeys = generatePrekeys()

        // STEP 1: Place Keys on Server (From Bob)
        X3DH.uploadPreKeys(Bob.podId, Bob.preKeys!!.getPublic())

        // STEP 2: Send the Initial Message (From Alice)
        Alice.sharedKey = X3DH.sendInitialMessage(Alice, Bob.podId, Bob.preKeys!!.privateIdentityPreKey, Alice.preKeys!!)

        // STEP 3: Process the Initial Message (From Bob)
        Bob.sharedKey = X3DH.processInitialMessage(Bob, Bob.podId, Bob.preKeys!!)

        assert(Alice.sharedKey.contentEquals(Bob.sharedKey))
    }

    @Test
    fun outOfOrderMessagesTest() {
        val Alice = User("alice")
        val Bob = User("bob")
        Alice.preKeys = generatePrekeys()
        Bob.preKeys = generatePrekeys()
        /* START X3DH */
        X3DH.uploadPreKeys(Bob.podId, Bob.preKeys!!.getPublic())
        Alice.sharedKey = X3DH.sendInitialMessage(Alice, Bob.podId, Bob.preKeys!!.privateIdentityPreKey, Alice.preKeys!!)
        Bob.sharedKey = X3DH.processInitialMessage(Bob, Bob.podId, Bob.preKeys!!)
        /* X3DH FINISHED - START DOUBLE RATCHET ALGORITHM */

        /*
            Alice sends A1 to start and creates A2 (so Bob doesn't receive now)
         */

        val messageA1 = Alice.sendInitialMessage("messageA1".toByteArray())
        val messageA2 = Alice.sendMessage("messageA2".toByteArray())

        val decryptA1 = Bob.receiveMessage(messageA1, messageA1.publicKey)

        /*
            Bob creates B1,2,3,4 but only sends B1 + B4
         */

        val messageB1 = Bob.sendMessage("messageB1".toByteArray())
        val messageB2 = Bob.sendMessage("messageB2".toByteArray())
        val messageB3 = Bob.sendMessage("messageB3".toByteArray())
        val messageB4 = Bob.sendMessage("messageB4".toByteArray())

        val decryptB1 = Alice.receiveMessage(messageB1, messageB1.publicKey)
        val decryptB4 = Alice.receiveMessage(messageB4, messageB4.publicKey)

        // Check if skipped messageKeys are determined
        assert(Alice.skippedKeys.size == 2)

        /*
            Alice sends A2 (so Bob receives now)
         */

        val decryptA2 = Bob.receiveMessage(messageA2, messageA2.publicKey)


        /*
            Bob sends B2 + B3
         */

        val decryptB2 = Alice.receiveMessage(messageB2, messageB2.publicKey)
        val decryptB3 = Alice.receiveMessage(messageB3, messageB3.publicKey)

        /*
            Alice creates and sends A3
         */

        val messageA3 = Alice.sendMessage("messageA3".toByteArray())
        val decryptA3 = Bob.receiveMessage(messageA3, messageA3.publicKey)

        /*
            Bob creates and send B5
         */

        val messageB5 = Bob.sendMessage("messageB5".toByteArray())
        val decryptB5 = Alice.receiveMessage(messageB5, messageB5.publicKey)


        // ASSERTIONS

        assert(Alice.skippedKeys.isEmpty())
        assert(Bob.skippedKeys.isEmpty())

        assert("messageA1" == decryptA1.plainText)
        assert("messageA2" == decryptA2.plainText)
        assert("messageB1" == decryptB1.plainText)
        assert("messageB2" == decryptB2.plainText)
        assert("messageB3" == decryptB3.plainText)
        assert("messageB4" == decryptB4.plainText)

        assert("messageA3" == decryptA3.plainText)
        assert("messageB5" == decryptB5.plainText)



        assert(messageA1.PN == 0)
        assert(messageA2.PN == 0)
        assert(messageB1.PN == 0)
        assert(messageB4.PN == 0)
        assert(messageB2.PN == 0)
        assert(messageB3.PN == 0)

        assert(messageA3.PN == 2)
        assert(messageB5.PN == 4)
    }
}
