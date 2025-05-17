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
    val targetPod = "alicebob"

    /*
        Initialize both Alice and Bob
     */
    alice.preKeys = generatePrekeys()
    bob.preKeys = generatePrekeys()

    X3DH.initiateSliceSchema(targetPod, authCode)
    X3DH.uploadPreKeys(targetPod, bob.preKeys!!.getPublic(), authCode)

    val maxRetries = 5
    var attempt = 0
    var currentDelay: Long = 200

    while (attempt < maxRetries) {
        try {
            alice.sharedKey = X3DH.sendInitialMessage(alice, targetPod, alice.preKeys!!, authCode)
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
            bob.sharedKey = X3DH.processInitialMessage(bob, targetPod, bob.preKeys!!, authCode)
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

    alice.sendInitialMessage(targetPod, "initialMessage".toByteArray(), timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
    bob.receiveMessage(targetPod, authCode, false, mocked)

    val valuesToEncrypt25 = getValuesToEncrypt(25)
    val valuesToEncrypt50 = getValuesToEncrypt(50)
    val valuesToEncrypt75 = getValuesToEncrypt(75)



    for (i in 1..tripleCount) {
        val json = generateJsonLdSum(i * 5)
        val jsonByteArray = json.toByteArray()
        val size = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt0 = emptyList<List<Statement>>()

        val timeAtomicEncrypt = measureNanoTime {
            alice.sendMessage(targetPod, jsonByteArray, timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
            val message = bob.receiveMessage(targetPod, authCode, false, mocked).first()
            val sum = getSumOfJsonLd(message.plainText)
        }
        results.add(BenchmarkResult("Atomic Encryption", size, timeAtomicEncrypt))

        messageController.deleteMessages(targetPod, authCode, mocked)

        val timePartialEncrypt25 = measureNanoTime {
            alice.sendMessage(targetPod, jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt25, tripleGroupsToEncrypt0, mocked)
            val message = messageController.retrieveMessages(alice.targetHashedPodId!!, targetPod, 0, emptyMap(), authCode, mocked).first()
            val sum = getSumOfJsonLd(String(message.cipherText, Charsets.UTF_8))
        }
        results.add(BenchmarkResult("Partial Encryption 25%", size, timePartialEncrypt25))

        messageController.deleteMessages(targetPod, authCode, mocked)

        val timePartialEncrypt50 = measureNanoTime {
            alice.sendMessage(targetPod, jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt50, tripleGroupsToEncrypt0, mocked)
            val message = messageController.retrieveMessages(alice.targetHashedPodId!!, targetPod, 0, emptyMap(), authCode, mocked).first()
            val sum = getSumOfJsonLd(String(message.cipherText, Charsets.UTF_8))
        }
        results.add(BenchmarkResult("Partial Encryption 50%", size, timePartialEncrypt50))

        messageController.deleteMessages(targetPod, authCode, mocked)

        val timePartialEncrypt75 = measureNanoTime {
            alice.sendMessage(targetPod, jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt75, tripleGroupsToEncrypt0, mocked)
            val message = messageController.retrieveMessages(alice.targetHashedPodId!!, targetPod, 0, emptyMap(), authCode, mocked).first()
            val sum = getSumOfJsonLd(String(message.cipherText, Charsets.UTF_8))
        }
        results.add(BenchmarkResult("Partial Encryption 75%", size, timePartialEncrypt75))

        messageController.deleteMessages(targetPod, authCode, mocked)

        printProgressBar(i, tripleCount)
    }


    return results
}
