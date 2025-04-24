package security.benchmarks

import security.User
import security.crypto.KeyUtils.generatePrekeys
import security.crypto.KeyUtils.generateX25519KeyPair
import security.messageController
import java.nio.ByteBuffer
import java.util.*
import kotlin.system.measureNanoTime

fun benchmarkWithoutAPI(tripleCount: Int): List<BenchmarkResult> {
    val results = mutableListOf<BenchmarkResult>()
    val mocked = true

    val alice = User("alice")
    val bob = User("bob")
    val authCode = ""
    val timestampBytes = ByteBuffer.allocate(8).putLong(System.currentTimeMillis()).array()

    /*
        Initialize both Alice and Bob
     */
    alice.preKeys = generatePrekeys()
    bob.preKeys = generatePrekeys()

    val (initialSharedKey, _) = generateX25519KeyPair()
    alice.sharedKey = initialSharedKey.encoded
    bob.sharedKey = initialSharedKey.encoded

    alice.DHKeyPair = generateX25519KeyPair()
    bob.DHKeyPair = generateX25519KeyPair()

    alice.initialDHPublicKey = bob.DHKeyPair!!.first.encoded
    alice.targetPublicKey = bob.preKeys!!.getPublic().publicIdentityPreKeyX25519.encoded



    bob.targetPublicKey = alice.preKeys!!.getPublic().publicIdentityPreKeyX25519.encoded

    alice.sendInitialMessage("bob", "initialMessage".toByteArray(), timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
    bob.receiveMessage("bob", authCode, false, mocked)

    val valuesToEncrypt = getValuesToEncrypt()

    for (i in 1..tripleCount) {
        val json = generateJsonLd(i * 5)
        val jsonByteArray = json.toByteArray()
        val size = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt = getTriplesToEncrypt(i * 5)

        val timeAtomicEncrypt = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
            bob.receiveMessage("bob", authCode, false, mocked)
        }
        results.add(BenchmarkResult("Atomic Encryption", size, timeAtomicEncrypt))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt, tripleGroupsToEncrypt, mocked)
            bob.receiveMessage("bob", authCode, true, mocked)
        }
        results.add(BenchmarkResult("Partial Encryption", size, timePartialEncrypt))

        messageController.deleteMessages("bob", authCode, mocked)

        printProgressBar(i, tripleCount)
    }

    return results
}