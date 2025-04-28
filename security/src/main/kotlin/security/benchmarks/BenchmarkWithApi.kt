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

fun benchmarkWithAPI(tripleCount: Int, authCode: String): List<BenchmarkResult> {
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
    val valuesToEncrypt75 = getValuesToEncrypt(75)

    for (i in 1..tripleCount) {
        val json = generateJsonLd(i * 5)
        val jsonByteArray = json.toByteArray()
        val size = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt0 = emptyList<List<Statement>>()
        val tripleGroupsToEncrypt100 = getTriplesToEncrypt(i * 5)

        val noEncrypt = measureNanoTime {
            alice.sendMessageNoEnc("bob", jsonByteArray, timestampBytes, authCode, mocked)
        }

        val noDecrypt = measureNanoTime {
            bob.receiveMessageNoEnc("bob", authCode, mocked)
        }
        results.add(BenchmarkResult("No Encryption", size, noEncrypt))
        results.add(BenchmarkResult("No Decryption", size, noDecrypt))

        messageController.deleteMessages("bob", authCode, mocked)

        val timeAtomicEncrypt = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
        }

        val timeAtomicDecrypt = measureNanoTime {
            bob.receiveMessage("bob", authCode, false, mocked)

        }
        results.add(BenchmarkResult("Atomic Encryption", size, timeAtomicEncrypt))
        results.add(BenchmarkResult("Atomic Decryption", size, timeAtomicDecrypt))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt25 = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt25, tripleGroupsToEncrypt0, mocked)
        }

        val timePartialDecrypt25 = measureNanoTime {
            bob.receiveMessage("bob", authCode, true, mocked)
        }
        results.add(BenchmarkResult("Partial Encryption 25%", size, timePartialEncrypt25))
        results.add(BenchmarkResult("Partial Decryption 25%", size, timePartialDecrypt25))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt50 = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt50, tripleGroupsToEncrypt0, mocked)
        }

        val timePartialDecrypt50 = measureNanoTime {
            bob.receiveMessage("bob", authCode, true, mocked)
        }
        results.add(BenchmarkResult("Partial Encryption 50%", size, timePartialEncrypt50))
        results.add(BenchmarkResult("Partial Decryption 50%", size, timePartialDecrypt50))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt75 = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt75, tripleGroupsToEncrypt0, mocked)
        }

        val timePartialDecrypt75 = measureNanoTime {
            bob.receiveMessage("bob", authCode, true, mocked)
        }
        results.add(BenchmarkResult("Partial Encryption 75%", size, timePartialEncrypt75))
        results.add(BenchmarkResult("Partial Decryption 75%", size, timePartialDecrypt75))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt100 = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt75, tripleGroupsToEncrypt100, mocked)
        }

        val timePartialDecrypt100 = measureNanoTime {
            bob.receiveMessage("bob", authCode, true, mocked)
        }
        results.add(BenchmarkResult("Partial Encryption 100%", size, timePartialEncrypt100))
        results.add(BenchmarkResult("Partial Decryption 100%", size, timePartialDecrypt100))

        messageController.deleteMessages("bob", authCode, mocked)

        printProgressBar(i, tripleCount)
    }


    return results
}
