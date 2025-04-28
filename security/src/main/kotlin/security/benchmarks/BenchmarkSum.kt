package security.benchmarks

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.apache.jena.rdf.model.Statement
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

    val valuesToEncrypt25 = getValuesToEncrypt(25)
    val valuesToEncrypt50 = getValuesToEncrypt(50)


    for (i in 1..tripleCount) {
        val json = generateJsonLdSum(i * 5)
        val jsonByteArray = json.toByteArray()
        val size = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt0 = emptyList<List<Statement>>()
        val tripleGroupsToEncrypt100 = getTriplesToEncrypt(i * 5)

        val timeAtomicEncrypt = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
            val message = bob.receiveMessage("bob", authCode, false, mocked).first()
            val sum = getSumOfJsonLd(message.plainText)
        }
        results.add(BenchmarkResult("Atomic Encryption", size, timeAtomicEncrypt))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt25 = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt25, tripleGroupsToEncrypt0, mocked)
            val message = messageController.retrieveMessages("bob", "bob", 0, emptyMap(), authCode, mocked).first()
            val sum = getSumOfJsonLd(String(message.cipherText, Charsets.UTF_8))
        }
        results.add(BenchmarkResult("Partial Encryption 25%", size, timePartialEncrypt25))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt50 = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt50, tripleGroupsToEncrypt0, mocked)
            val message = messageController.retrieveMessages("bob", "bob", 0, emptyMap(), authCode, mocked).first()
            val sum = getSumOfJsonLd(String(message.cipherText, Charsets.UTF_8))
        }
        results.add(BenchmarkResult("Partial Encryption 50%", size, timePartialEncrypt50))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt75 = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt50, tripleGroupsToEncrypt100, mocked)
            val message = messageController.retrieveMessages("bob", "bob", 0, emptyMap(), authCode, mocked).first()
            val sum = getSumOfJsonLd(String(message.cipherText, Charsets.UTF_8))
        }
        results.add(BenchmarkResult("Partial Encryption 75%", size, timePartialEncrypt75))

        messageController.deleteMessages("bob", authCode, mocked)

        printProgressBar(i, tripleCount)
    }


    return results
}
