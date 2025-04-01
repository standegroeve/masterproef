package partialEncrypt

import com.github.jsonldjava.core.JsonLdProcessor
import com.github.jsonldjava.utils.JsonUtils
import security.partialEncrypt.RDFTransformer
import kotlin.test.Test

class testPredicateTransform {
    val randomKey = security.crypto.generateX25519KeyPair().first
    val associatedData = ByteArray(16)

    val predicatesToEncrypt = listOf(
        "http://example.org/hasName",
        "http://example.org/hasAge"
    )

    @Test
    fun objectTransfrom() {
        val jsonString = """
            {
                "@context": { "ex": "http://example.org/" },
                "@id": "ex:person1",
                "@type": "ex:Person",
                "ex:hasName": "John Doe",
                "ex:hasAge": 30
            }
            """.trimIndent()

        val map = JsonUtils.fromString(jsonString) as Map<String, Any>
        val expandedMap = (JsonLdProcessor.expand(map)[0]) as Map<String, Any>
        val encryptedMap = RDFTransformer.encrypt(expandedMap, randomKey.encoded, associatedData, predicatesToEncrypt)
        val objTransformedMap = RDFTransformer.objectTransform(jsonMap = encryptedMap).first
        val predTransformedMap = RDFTransformer.predicateTransform(jsonMap = objTransformedMap)


    }

    @Test
    fun objectPredicateTransform() {
        val jsonString = """
            {
                "@context": { "ex": "http://example.org/" },
                "@id": "ex:person1",
                "@type": "ex:Person",
                "ex:hasName": 30,
                "ex:hasAge": 30
            }
            """.trimIndent()

        val map = JsonUtils.fromString(jsonString) as Map<String, Any>
        val expandedMap = (JsonLdProcessor.expand(map)[0]) as Map<String, Any>
        val encryptedMap = RDFTransformer.encrypt(expandedMap, randomKey.encoded, associatedData, predicatesToEncrypt)
        val transformedMap = RDFTransformer.encryptionTransform(encryptedMap = encryptedMap)

        assert(transformedMap.size == 7)

        val a = 2
    }
}