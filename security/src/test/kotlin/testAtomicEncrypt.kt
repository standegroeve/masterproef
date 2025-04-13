import org.junit.jupiter.api.Test
import security.*
import security.crypto.generatePrekeys
import java.nio.ByteBuffer


class securityTests() {

//    private val authCode = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJLcEFaaHhiUGVrZnN4WGdMLTA1VkZaQ1V4dkx2ZnNhWnpwR2V4LWVEaV80In0.eyJleHAiOjE3NDE1NzgyNjEsImlhdCI6MTc0MTU0OTQ3NiwiYXV0aF90aW1lIjoxNzQxNTQ5NDYxLCJqdGkiOiI1NmU3OTQwNy0yYzY1LTRkMWUtODZhMi03NjZkZDdiYmFkNzAiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgyODAvcmVhbG1zL2FsaWNlIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImVkMDQ1YmM2LTA2YTUtNGI2Yi05MWYyLTcxN2RmODBhNDRiYyIsInR5cCI6IkJlYXJlciIsImF6cCI6Im15LXB1YmxpYy1jbGllbnQiLCJzaWQiOiIxNGQ0Y2Y3Yi0zY2E1LTRiNmMtYmFmYi1lYzU2NzUwMzM3YzciLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6NDIwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib3duZXIiLCJkZWZhdWx0LXJvbGVzLWFsaWNlIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIERlbW8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiRGVtbyIsImVtYWlsIjoiYWxpY2VAZXhhbXBsZS5vcmcifQ.eLyi6zzLi6qy4y6u5r7kVxKxaz5diWaa4jqoXICunalpIqx1UmfCjTya68VhmO-HJElEaxTc8H-Omqax9476jVeoAMQGNxm_zd6xQdM2qvC7qyWbcGwdSGZU6MC7GQUJ7NYYbI3fpY3aLhKCrGwYir4XilA0ixudbU9bdEz819_saSDIFmz5K7Y85WMbpdjfc7hTMagBZ_rBfA2Z4raUw08T_YaB190ShAeuy3B9IC97nf0wj-dIK0xlz2rF8KlL-oA0OYlRYCADsafOSPmwhI3CVcg1D-0LY9OIKZsjbTT-fBjasQQ6KaURE8w5d3mTnggEy9sNlaEzvrgY3puCPQ"
//    val keepStructure = false
//
//    @Test
//    fun testGetPublicPrekeys() {
//        val Alice = User("alice")
//        val Bob = User("bob")
//        Alice.preKeys = generatePrekeys()
//        Bob.preKeys = generatePrekeys()
//
//        //val test = X3DH.getPublicX3DHKeys("bob", authCode)
//        val a = 2
//        assert(true)
//    }
//
//    @Test
//    fun X3DHTest() {
//        // STEP 0: Generate Prekeys
//        val Alice = User("alice")
//        val Bob = User("bob")
//        Alice.preKeys = generatePrekeys()
//        Bob.preKeys = generatePrekeys()
//
//        X3DH.initiateSliceSchema("bob", authCode)
//
//        // STEP 1: Place Keys on Server (From Bob)
//        X3DH.uploadPreKeys(Bob.podId, Bob.preKeys!!.getPublic(), authCode)
//
//        // STEP 2: Send the Initial Message (From Alice)
//        Alice.sharedKey = X3DH.sendInitialMessage(Alice, Bob.podId, Alice.preKeys!!, authCode)
//
//        // STEP 3: Process the Initial Message (From Bob)
//        Bob.sharedKey = X3DH.processInitialMessage(Bob, Bob.podId, Bob.preKeys!!, authCode)
//
//        assert(Alice.sharedKey.contentEquals(Bob.sharedKey))
//    }
//
//    @Test
//    fun outOfOrderMessagesTest() {
//        val targetPodId = "bob"
//        val Alice = User("alice")
//        val Bob = User("bob")
//        Alice.preKeys = generatePrekeys()
//        Bob.preKeys = generatePrekeys()
//        /* START X3DH */
//        X3DH.uploadPreKeys(Bob.podId, Bob.preKeys!!.getPublic(), authCode)
//        Alice.sharedKey = X3DH.sendInitialMessage(Alice, Bob.podId, Alice.preKeys!!, authCode)
//        Bob.sharedKey = X3DH.processInitialMessage(Bob, Bob.podId, Bob.preKeys!!, authCode)
//        /* X3DH FINISHED - START DOUBLE RATCHET ALGORITHM */
//
//        /*
//            Alice sends A1 to start and creates A2 (so Bob doesn't receive now)
//         */
//        val timestamp = System.currentTimeMillis()
//
//        Alice.sendInitialMessage(targetPodId, "messageA1".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp).array(), authCode, keepStructure)
//        Alice.sendMessage(targetPodId, "messageA2".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+1).array(), authCode, keepStructure)
//
//        val decryptA1 = Bob.receiveMessage(targetPodId, authCode, keepStructure)
//
//        /*
//            Bob creates B1,2,3,4 but only sends B1 + B4
//         */
//
//        val messageB1 = Bob.sendMessage(targetPodId, "messageB1".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+2).array(), authCode, keepStructure)
//        val messageB2 = Bob.sendMessage(targetPodId, "messageB2".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+3).array(), authCode, keepStructure)
//        val messageB3 = Bob.sendMessage(targetPodId, "messageB3".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+4).array(), authCode, keepStructure)
//        val messageB4 = Bob.sendMessage(targetPodId, "messageB4".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+5).array(), authCode, keepStructure)
//
//        val decryptB1234 = Alice.receiveMessage(targetPodId, authCode, keepStructure)
//
//        /*
//            Alice creates and sends A3
//         */
//
//        val messageA3 = Alice.sendMessage(targetPodId, "messageA3".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+6).array(), authCode, keepStructure)
//        val decryptA3 = Bob.receiveMessage(targetPodId, authCode, keepStructure)
//
//        /*
//            Bob creates and send B5
//         */
//
//        val messageB5 = Bob.sendMessage(targetPodId, "messageB5".toByteArray(), ByteBuffer.allocate(8).putLong(timestamp+7).array(), authCode, keepStructure)
//        val decryptB5 = Alice.receiveMessage(targetPodId, authCode, keepStructure)
//
//
//        // ASSERTIONS
//
//        assert(Alice.skippedKeys.isEmpty())
//        assert(Bob.skippedKeys.isEmpty())
//
//        assert("messageA1" == decryptA1[0].plainText)
//        assert("messageA2" == decryptA1[1].plainText)
//        assert("messageB1" == decryptB1234[0].plainText)
//        assert("messageB2" == decryptB1234[1].plainText)
//        assert("messageB3" == decryptB1234[2].plainText)
//        assert("messageB4" == decryptB1234[3].plainText)
//
//        assert("messageA3" == decryptA3[0].plainText)
//        assert("messageB5" == decryptB5[0].plainText)
//
//
//
////        assert(messageA1.PN == 0)
////        assert(messageA2.PN == 0)
////        assert(messageB1.PN == 0)
////        assert(messageB4.PN == 0)
////        assert(messageB2.PN == 0)
////        assert(messageB3.PN == 0)
////
////        assert(messageA3.PN == 2)
////        assert(messageB5.PN == 4)
//    }
}
