package security.benchmarks

import org.apache.jena.rdf.model.Statement
import security.User
import security.crypto.KeyUtils.generatePrekeys
import security.crypto.KeyUtils.generateX25519KeyPair
import security.messageController
import java.nio.ByteBuffer
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

    alice.targetHashedPodId = "hashedPodIdMockedB"
    bob.targetHashedPodId = "hashedPodIdMockedA"

    alice.hashedPodId = "hashedPodIdMockedA"
    bob.hashedPodId = "hashedPodIdMockedB"

    bob.targetPublicKey = alice.preKeys!!.getPublic().publicIdentityPreKeyX25519.encoded

    alice.sendInitialMessage("alicebob", "initialMessage".toByteArray(), timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
    bob.receiveMessage("alicebob", authCode, false, mocked)

    val valuesToEncrypt25 = getValuesToEncrypt(25)
    val valuesToEncrypt50 = getValuesToEncrypt(50)
    val valuesToEncrypt75 = getValuesToEncrypt(75)
    val valuesToEncrypt100 = getValuesToEncrypt(100)


    for (i in 1..tripleCount) {
        val json = generateJsonLd(i * 5)
        val jsonByteArray = json.toByteArray()
        val size = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt0 = emptyList<List<Statement>>()

        val timeAtomicEncrypt = measureNanoTime {
            alice.sendMessage("alicebob", jsonByteArray, timestampBytes, authCode, false, emptyList(), emptyList(), mocked)
        }

        val timeAtomicDecrypt = measureNanoTime {
            bob.receiveMessage("alicebob", authCode, false, mocked)

        }
        results.add(BenchmarkResult("Atomic Encryption", size, timeAtomicEncrypt))
        results.add(BenchmarkResult("Atomic Decryption", size, timeAtomicDecrypt))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt25 = measureNanoTime {
            alice.sendMessage("alicebob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt25, tripleGroupsToEncrypt0, mocked)
        }

        val timePartialDecrypt25 = measureNanoTime {
            bob.receiveMessage("alicebob", authCode, true, mocked)
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

        messageController.deleteMessages("alicebob", authCode, mocked)

        val timePartialEncrypt75 = measureNanoTime {
            alice.sendMessage("alicebob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt75, tripleGroupsToEncrypt0, mocked)
        }

        val timePartialDecrypt75 = measureNanoTime {
            bob.receiveMessage("alicebob", authCode, true, mocked)
        }
        results.add(BenchmarkResult("Partial Encryption 75%", size, timePartialEncrypt75))
        results.add(BenchmarkResult("Partial Decryption 75%", size, timePartialDecrypt75))

        messageController.deleteMessages("bob", authCode, mocked)

        val timePartialEncrypt100 = measureNanoTime {
            alice.sendMessage("alicebob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt100, tripleGroupsToEncrypt0, mocked)
        }

        val timePartialDecrypt100 = measureNanoTime {
            bob.receiveMessage("alicebob", authCode, true, mocked)
        }
        results.add(BenchmarkResult("Partial Encryption 100%", size, timePartialEncrypt100))
        results.add(BenchmarkResult("Partial Decryption 100%", size, timePartialDecrypt100))

        messageController.deleteMessages("bob", authCode, mocked)

        printProgressBar(i, tripleCount)
    }

    return results
}