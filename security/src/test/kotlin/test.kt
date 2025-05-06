import org.junit.jupiter.api.Test
import security.*
import security.crypto.KeyUtils.generatePrekeys
import java.nio.ByteBuffer


class securityTests() {

    private val authCode = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJsaXBYUFRRMHdud0FIaGpJdWdOdWNoYXRESk5KOEI0UFJvTEFLU3kzcFpnIn0.eyJleHAiOjE3NDY1Njc1MTAsImlhdCI6MTc0NjU1NjcxMCwiYXV0aF90aW1lIjoxNzQ2NTU2Njk1LCJqdGkiOiJmYWYwYjZkYi0yOWI1LTQ0ZmMtYmIxZS1kODg0ZTg0YzkwYjYiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgyODAvcmVhbG1zL2FsaWNlYm9iIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjI3ZTdlMmQyLTQyZWUtNGI3YS1iMGI5LTUzOGM3ZDEwZjM3NiIsInR5cCI6IkJlYXJlciIsImF6cCI6InB1YmxpYy1jbGllbnQiLCJzaWQiOiJjZjk0NTYwYy0xYzdlLTRjZDMtOGQ2MS1lNzk3MTIwNTZjNTQiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6NDIwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib3duZXIiLCJkZWZhdWx0LXJvbGVzLWFsaWNlYm9iIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlYm9iIERlbW8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZWJvYiIsImdpdmVuX25hbWUiOiJBbGljZWJvYiIsImZhbWlseV9uYW1lIjoiRGVtbyIsImVtYWlsIjoiYWxpY2Vib2JAZXhhbXBsZS5vcmcifQ.mTR7GGEG0AZqESlz34829nTDFc8GyiPjo0pVSSELw5PenhNvWp_pMpid2JvpFtGZ7gUu6L9gh3dav3bcfqXeOG-d2HiEpVnPdnpIHZtgeD7t8xPO7z3eOck81k7bE21kz1SMVctY8lFgp0vJ35bsgkntZhYPnKswvV_381ALpVWTw6hpI3jdcpG2w15XbRSpCgk05E1W62KEkVxt0bfxJmYLNW67Wc1aUsgiUrAkdH48wYvU_pijrzB1xfwF0tw7TBufhXRikDXpVcny6f3MgXRB82eOHAQ5GBI4FmGSyUSA-MnbIq8N4HU9Y6oa8vbVOp_QZ2HWx8pBLQGU8dbKXA"

    @Test
    fun testGetPublicPrekeys() {
        val commonPod = "alicebob"

        val Alice = User("alice")
        val Bob = User("bob")
        Alice.preKeys = generatePrekeys()
        Bob.preKeys = generatePrekeys()

        //val test = X3DH.getPublicX3DHKeys("bob", authCode)
        val a = 2
        assert(true)
    }

    @Test
    fun X3DHTest() {
        // STEP 0: Generate Prekeys
        val Alice = User("alice")
        val Bob = User("bob")
        Alice.preKeys = generatePrekeys()
        Bob.preKeys = generatePrekeys()

        X3DH.initiateSliceSchema("bob", authCode)

        // STEP 1: Place Keys on Server (From Bob)
        X3DH.uploadPreKeys(Bob.podId, Bob.preKeys!!.getPublic(), authCode)

        // STEP 2: Send the Initial Message (From Alice)
        Alice.sharedKey = X3DH.sendInitialMessage(Alice, Bob.podId, Alice.preKeys!!, authCode)

        // STEP 3: Process the Initial Message (From Bob)
        Bob.sharedKey = X3DH.processInitialMessage(Bob, Bob.podId, Bob.preKeys!!, authCode)

        assert(Alice.sharedKey.contentEquals(Bob.sharedKey))
    }

    @Test
    fun outOfOrderMessagesTest() {
        val commonPod = "alicebob"

        val targetPodId = "bob"
        val Alice = User("alice")
        val Bob = User("bob")
        Alice.preKeys = generatePrekeys()
        Bob.preKeys = generatePrekeys()
        /* START X3DH */
        X3DH.uploadPreKeys(commonPod, Bob.preKeys!!.getPublic(), authCode)
        Alice.sharedKey = X3DH.sendInitialMessage(Alice, commonPod, Alice.preKeys!!, authCode)
        Bob.sharedKey = X3DH.processInitialMessage(Bob, commonPod, Bob.preKeys!!, authCode)
        /* X3DH FINISHED - START DOUBLE RATCHET ALGORITHM */

        /*
            Alice sends A1 to start and creates A2 (so Bob doesn't receive now)
         */
        val timestamp = System.currentTimeMillis()

        Alice.sendInitialMessage(commonPod, "messageA1".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp).array(), authCode)
        Alice.sendMessage(commonPod, "messageA2".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+1).array(), authCode)

        val decryptA1 = Bob.receiveMessage(commonPod, authCode)

        /*
            Bob creates B1,2,3,4 but only sends B1 + B4
         */

        val messageB1 = Bob.sendMessage(commonPod, "messageB1".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+2).array(), authCode)
        val messageB2 = Bob.sendMessage(commonPod, "messageB2".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+3).array(), authCode)
        val messageB3 = Bob.sendMessage(commonPod, "messageB3".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+4).array(), authCode)
        val messageB4 = Bob.sendMessage(commonPod, "messageB4".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+5).array(), authCode)

        val decryptB1234 = Alice.receiveMessage(commonPod, authCode)

        /*
            Alice creates and sends A3
         */

        val messageA3 = Alice.sendMessage(commonPod, "messageA3".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+6).array(), authCode)
        val decryptA3 = Bob.receiveMessage(commonPod, authCode)

        /*
            Bob creates and send B5
         */

        val messageB5 = Bob.sendMessage(commonPod, "messageB5".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+7).array(), authCode)
        val decryptB5 = Alice.receiveMessage(commonPod, authCode)


        // ASSERTIONS

        assert(Alice.skippedKeys.isEmpty())
        assert(Bob.skippedKeys.isEmpty())

        assert("messageA1" == decryptA1[0].plainText)
        assert("messageA2" == decryptA1[1].plainText)
        assert("messageB1" == decryptB1234[0].plainText)
        assert("messageB2" == decryptB1234[1].plainText)
        assert("messageB3" == decryptB1234[2].plainText)
        assert("messageB4" == decryptB1234[3].plainText)

        assert("messageA3" == decryptA3[0].plainText)
        assert("messageB5" == decryptB5[0].plainText)



//        assert(messageA1.PN == 0)
//        assert(messageA2.PN == 0)
//        assert(messageB1.PN == 0)
//        assert(messageB4.PN == 0)
//        assert(messageB2.PN == 0)
//        assert(messageB3.PN == 0)
//
//        assert(messageA3.PN == 2)
//        assert(messageB5.PN == 4)
    }
}
