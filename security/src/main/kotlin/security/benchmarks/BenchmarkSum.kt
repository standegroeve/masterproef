package security.benchmarks

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import security.User
import security.X3DH
import security.crypto.KeyUtils.generatePrekeys
import security.messageController
import java.nio.ByteBuffer
import kotlin.system.measureNanoTime

fun benchmarkSum(tripleCount: Int, authCode: String): List<BenchmarkResult> {
    val results = mutableListOf<BenchmarkResult>()
    val mocked = false

    val alice = User("alice")
    val bob = User("bob")
    val timestampBytes = ByteBuffer.allocate(8).putLong(System.currentTimeMillis()).array()

    /*
        Initialize both Alice and Bob
     */
    alice.preKeys = generatePrekeys()
    bob.preKeys = generatePrekeys()

    X3DH.initiateSliceSchema(bob.podId, authCode)
    X3DH.uploadPreKeys(bob.podId, bob.preKeys!!.getPublic(), authCode)

    val maxRetries = 5
    var attempt = 0
    var currentDelay: Long = 200

    while (attempt < maxRetries) {
        try {
            alice.sharedKey = X3DH.sendInitialMessage(alice, bob.podId, alice.preKeys!!, authCode)
            break
        }
        catch (e: RuntimeException) {
            runBlocking {
                delay(currentDelay)
            }
            currentDelay *= 2
            attempt++
            if (attempt == maxRetries) {
                throw Error("Too much tries!!!!!")
            }
        }
    }

    attempt = 0
    currentDelay = 200

    while (attempt < maxRetries) {
        try {
            bob.sharedKey = X3DH.processInitialMessage(bob, bob.podId, bob.preKeys!!, authCode)
            break
        }
        catch (e: RuntimeException) {
            runBlocking {
                delay(currentDelay)
            }
            currentDelay *= 2
            attempt++
            if (attempt == maxRetries) {
                throw Error("Too much tries!!!!!")
            }
        }
    }

    alice.sendInitialMessage("bob", "initialMessage".toByteArray(), timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
    bob.receiveMessage("bob", authCode, false, mocked)

    val valuesToEncrypt = getValuesToEncrypt()

    for (i in 1..tripleCount) {
        val json = generateJsonLdSum(i * 5)
        val jsonByteArray = json.toByteArray()
        val size = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt = getTriplesToEncrypt(i * 5)

        val timeAtomicEncrypt = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
            bob.receiveMessage("bob", authCode, false, mocked).first()
        }
        results.add(BenchmarkResult("Atomic Encryption", size, timeAtomicEncrypt))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt, tripleGroupsToEncrypt, mocked)
            messageController.retrieveMessages("bob", "bob", 0, emptyMap(), authCode, mocked).first()
        }
        results.add(BenchmarkResult("Partial Encryption", size, timePartialEncrypt))

        messageController.deleteMessages("bob", authCode, mocked)

        printProgressBar(i, tripleCount)
    }


    return results
}
