package security

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.apache.jena.rdf.model.ModelFactory
import org.apache.jena.rdf.model.Statement
import org.apache.jena.riot.RDFDataMgr
import org.apache.jena.riot.RDFFormat
import security.crypto.generatePrekeys
import security.crypto.generateX25519KeyPair
import java.io.File
import java.io.StringReader
import java.io.StringWriter
import java.nio.ByteBuffer
import java.util.*
import kotlin.system.measureNanoTime

data class BenchmarkResult(
    @JsonProperty("encryptionType") val label: String,
    @JsonProperty("sizeInBytes") val size: Int,
    @JsonProperty("durationNs") val time: Long
)

fun generateJsonLd(tripleCount: Int): String {
    val model = ModelFactory.createDefaultModel()

    model.setNsPrefix("ex", "http://example.org/")
    model.setNsPrefix("renc", "http://www.w3.org/ns/renc#")

    for (i in 0 until tripleCount) {
        val subject = model.createResource("ex:$i")
        model.add(subject, model.createProperty("ex:name"), "Name$i")
        model.add(subject, model.createProperty("ex:description"), "Description$i")

        val relatedNumber = i + tripleCount
        val relatedSubject = model.createResource("ex:$relatedNumber")

        model.add(subject, model.createProperty("ex:relatedTo"), relatedSubject)
        model.add(relatedSubject, model.createProperty("ex:name"), "Name$relatedNumber")

    }

    val out = StringWriter()
    RDFDataMgr.write(out, model, RDFFormat.JSONLD_PRETTY)
    return out.toString()
}

private fun getValuesToEncrypt(): List<String> {
    val valuesToEncryptModel = ModelFactory.createDefaultModel()
    val valuesToEncryptJsonString = """
            {
                "@context": {
                    "ex": "http://example.org/",
                    "renc": "http://www.w3.org/ns/renc#"
                },
                "@id": "ex:encryptionValues",
                "ex:valuesToEncrypt": [
                    { "@id": "ex:name" },
                    { "@id": "ex:description" }
                ]
            }
            """.trimIndent()

    valuesToEncryptModel.read(StringReader(valuesToEncryptJsonString), null, "JSON-LD")

    val encryptionConfigRes = valuesToEncryptModel.getResource("http://example.org/encryptionValues")
    val propertyToEncrypt = valuesToEncryptModel.getProperty("http://example.org/valuesToEncrypt")

    val valuesToEncryptList = valuesToEncryptModel.listObjectsOfProperty(encryptionConfigRes, propertyToEncrypt)
        .toList()
        .map { it.asResource().uri }

    return  valuesToEncryptList
}

private fun getTriplesToEncrypt(tripleCount: Int): List<List<Statement>> {
    val groupsToEncryptModel = ModelFactory.createDefaultModel()

    val graphString = StringBuilder()

    for (i in 0 until tripleCount) {
        if (i > 0) {
            graphString.append(",")
        }

        val number = i + tripleCount

        graphString.append("""
            {
                "@id": "ex:$number",
                "ex:name": "Name$number"
            }
        """.trimIndent())
    }


    val tripleGroupsToEncryptString = """
            {
                "@context": {
                    "ex": "http://example.org/",
                    "renc": "http://www.w3.org/ns/renc#"
                },
                "@graph": [
                    $graphString
                ]
            }
            """.trimIndent()

    groupsToEncryptModel.read(StringReader(tripleGroupsToEncryptString), null, "JSON-LD")

    val tripleGroupsToEncrypt = groupsToEncryptModel.listStatements().toList()
        .groupBy { it.subject }
        .values.toList()

    return tripleGroupsToEncrypt
}

fun main() {
    val results = mutableListOf<BenchmarkResult>()
    val alice = User("Alice")
    val bob = User("Bob")
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

    println("1: ${Base64.getEncoder().encodeToString(alice.sharedKey)}")
    println("1: ${Base64.getEncoder().encodeToString(bob.sharedKey)}")

    alice.sendInitialMessage("bob", "initialMessage".toByteArray(), timestampBytes, authCode, false)
    bob.receiveMessage("bob", authCode, false)

    val valuesToEncrypt = getValuesToEncrypt()

    for (i in 1..500) {
        val json = generateJsonLd(i * 5)
        val jsonByteArray = json.toByteArray()
        val size = json.toByteArray(Charsets.UTF_8).size

        val tripleGroupsToEncrypt = getTriplesToEncrypt(i * 5)

        val timeAtomicEncrypt = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, false)
            bob.receiveMessage("bob", authCode, false)
        }
        results.add(BenchmarkResult("Atomic Encryption", size, timeAtomicEncrypt))

        val timePartialEncrypt = measureNanoTime {
            alice.sendMessage("bob", jsonByteArray, timestampBytes, authCode, true, valuesToEncrypt, tripleGroupsToEncrypt)
            bob.receiveMessage("bob", authCode, true)
        }
        results.add(BenchmarkResult("Partial Encryption", size, timePartialEncrypt))

        val mapper = jacksonObjectMapper()
        mapper.writerWithDefaultPrettyPrinter()
            .writeValue(File("benchmark_results.json"), results)
    }

}