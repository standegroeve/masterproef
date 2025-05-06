package security.benchmarks

import org.apache.jena.rdf.model.Statement
import security.crypto.CryptoUtils
import security.crypto.KeyUtils
import security.partialEncrypt.RDFEncryptionProcessor
import java.nio.ByteBuffer
import java.nio.charset.Charset

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
        val jsonOriginalSize = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt0 = emptyList<List<Statement>>()
        val tripleGroupsToEncrypt100 = getTriplesToEncrypt(i)

        val atomicEncryptJSON = CryptoUtils.aesGcmEncrypt(jsonByteArray, randomKey.encoded, associatedData)
        val overheadPercentageAtomicJSON = ((atomicEncryptJSON!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Atomic Encryption JSON-LD", jsonOriginalSize, atomicEncryptJSON.size, overheadPercentageAtomicJSON))

        val partialEncrypt25JSON = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt25, tripleGroupsToEncrypt0).toByteArray()
        val overheadPercentagePartial25JSON = ((partialEncrypt25JSON!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 25% JSON-LD", jsonOriginalSize, partialEncrypt25JSON.size, overheadPercentagePartial25JSON))

        val partialEncrypt50JSON = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt50, tripleGroupsToEncrypt0).toByteArray()
        val overheadPercentagePartial50JSON = ((partialEncrypt50JSON!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 50% JSON-LD", jsonOriginalSize, partialEncrypt50JSON.size, overheadPercentagePartial50JSON))

        val partialEncrypt75JSON = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt75, tripleGroupsToEncrypt0).toByteArray()
        val overheadPercentagePartial75JSON = ((partialEncrypt75JSON!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 75% JSON-LD", jsonOriginalSize, partialEncrypt75JSON.size, overheadPercentagePartial75JSON))

        val partialEncrypt100JSON = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt75, tripleGroupsToEncrypt100).toByteArray()
        val overheadPercentagePartial100JSON = ((partialEncrypt100JSON!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 100% JSON-LD", jsonOriginalSize, partialEncrypt100JSON.size, overheadPercentagePartial100JSON))



        val atomicEncryptTurtle = CryptoUtils.aesGcmEncrypt(jsonByteArray, randomKey.encoded, associatedData)
        val overheadPercentageAtomicTurtle = ((atomicEncryptTurtle!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Atomic Encryption Turtle", jsonOriginalSize, atomicEncryptTurtle.size, overheadPercentageAtomicTurtle))

        val partialEncrypt25Turtle = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt25, tripleGroupsToEncrypt0,  returnType = "Turtle").toByteArray()
        val overheadPercentagePartial25Turtle = ((partialEncrypt25Turtle!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 25% Turtle", jsonOriginalSize, partialEncrypt25Turtle.size, overheadPercentagePartial25Turtle))

        val partialEncrypt50Turtle = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt50, tripleGroupsToEncrypt0, returnType = "Turtle").toByteArray()
        val overheadPercentagePartial50Turtle = ((partialEncrypt50Turtle!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 50% Turtle", jsonOriginalSize, partialEncrypt50Turtle.size, overheadPercentagePartial50Turtle))

        val partialEncrypt75Turtle = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt75, tripleGroupsToEncrypt0, returnType = "Turtle").toByteArray()
        val overheadPercentagePartial75Turtle = ((partialEncrypt75Turtle!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 75% Turtle", jsonOriginalSize, partialEncrypt75Turtle.size, overheadPercentagePartial75Turtle))

        val partialEncrypt100Turtle = RDFEncryptionProcessor.encryptRDF(json, timestampBytes, randomKey.encoded, associatedData, valuesToEncrypt75, tripleGroupsToEncrypt100, returnType = "Turtle").toByteArray()
        val overheadPercentagePartial100Turtle = ((partialEncrypt100Turtle!!.size - jsonOriginalSize).toDouble() / jsonOriginalSize) * 100
        results.add(StorageBenchmarkResult("Partial Encryption 100% Turtle", jsonOriginalSize, partialEncrypt100Turtle.size, overheadPercentagePartial100Turtle))


        printProgressBar(i, tripleCount)
    }

    return results
}