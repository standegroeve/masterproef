package security.benchmarks

import org.apache.jena.rdf.model.Statement
import org.bouncycastle.pqc.jcajce.provider.util.KeyUtil
import security.User
import security.crypto.CryptoUtils
import security.crypto.KeyUtils
import security.messageController
import security.partialEncrypt.RDFEncryptionProcessor
import java.nio.ByteBuffer
import kotlin.system.measureNanoTime

fun encryptionOverheadMeasurer(tripleCount: Int): List<StorageBenchmarkResult> {
    val results = mutableListOf<StorageBenchmarkResult>()
    val mocked = true

    val (randomKey,_) = KeyUtils.generateX25519KeyPair()

    val associatedData = randomKey.encoded + randomKey.encoded!! + randomKey.encoded

    val authCode = ""
    val timestampBytes = ByteBuffer.allocate(8).putLong(System.currentTimeMillis()).array()

    val valuesToEncrypt25 = getValuesToEncrypt(25)
    val valuesToEncrypt50 = getValuesToEncrypt(50)
    val valuesToEncrypt75 = getValuesToEncrypt(75)

    for (i in 1..tripleCount) {
        val json = generateJsonLd(i * 5)
        val jsonByteArray = json.toByteArray()
        val originalSize = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt0 = emptyList<List<Statement>>()
        val tripleGroupsToEncrypt100 = getTriplesToEncrypt(i * 5)

        val atomicEncrypt = CryptoUtils.aesGcmEncrypt(jsonByteArray, randomKey.encoded, associatedData)
        val overheadPercentageAtomic = ((atomicEncrypt!!.size - originalSize).toDouble() / originalSize) * 100
        results.add(StorageBenchmarkResult("Atomic Encryption", originalSize, atomicEncrypt.size, overheadPercentageAtomic))

        val partialEncrypt25 = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt25, tripleGroupsToEncrypt0).toByteArray()
        val overheadPercentagePartial25 = ((partialEncrypt25!!.size - originalSize).toDouble() / originalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 25%", originalSize, partialEncrypt25.size, overheadPercentagePartial25))

        val partialEncrypt50 = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt50, tripleGroupsToEncrypt0).toByteArray()
        val overheadPercentagePartial50 = ((partialEncrypt50!!.size - originalSize).toDouble() / originalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 50%", originalSize, partialEncrypt50.size, overheadPercentagePartial50))

        val partialEncrypt75 = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt75, tripleGroupsToEncrypt0).toByteArray()
        val overheadPercentagePartial75 = ((partialEncrypt75!!.size - originalSize).toDouble() / originalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 75%", originalSize, partialEncrypt75.size, overheadPercentagePartial75))

        val partialEncrypt100 = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt75, tripleGroupsToEncrypt100).toByteArray()
        val overheadPercentagePartial100 = ((partialEncrypt100!!.size - originalSize).toDouble() / originalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 100%", originalSize, partialEncrypt100.size, overheadPercentagePartial100))

        printProgressBar(i, tripleCount)
    }

    return results
}