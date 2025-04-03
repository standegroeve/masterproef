import com.github.jsonldjava.core.JsonLdProcessor
import com.github.jsonldjava.utils.JsonUtils
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Test
import security.partialEncrypt.RDFTransformer
import security.crypto.generateX25519KeyPair
import security.partialEncrypt.RDFEncryptionProcessor

class transformTests() {

    val predicatesToEncrypt = listOf(
        "http://example.org/hasName",
        "http://example.org/hasAge"
    )


    @Test
    fun readAndExpand() {
        val jsonString = """
            {
              "@context": { "ex": "http://example.org/" },
              "@id": "ex:person1",
              "@type": "ex:Person",
              "ex:hasName": "John Doe",
              "ex:hasAge": 30,
              "ex:address": {
                "ex:street": "123 Main St",
                "ex:city": {
                  "ex:name": "Springfield",
                  "ex:state": "Illinois"
                }
              },
              "ex:hasChildren": [
                {
                  "@id": "ex:child1",
                  "ex:hasName": "Jane Doe",
                  "ex:hasAge": "10"
                },
                {
                  "@id": "ex:child2",
                  "ex:hasName": "Jack Doe",
                  "ex:hasAge": "7"
                }
              ]
            }
            """.trimIndent()

        val map = JsonUtils.fromString(jsonString) as Map<String, Any>

        assert(map.size == 7)
        assert((map["@context"] as Map<String, Any>).size == 1)
        assert((map["ex:hasChildren"] as List<Map<String, Any>>).size == 2)
        assert((map["ex:address"] as Map<String, Any>).containsKey("ex:city"))
        assert(((map["ex:address"] as Map<String, Any>).get("ex:city") as Map<String, Any>).size == 2)

        val expandedMap = (JsonLdProcessor.expand(map)[0]) as Map<String, Any>

        assert(expandedMap.containsKey("http://example.org/hasName"))
        assert(expandedMap.containsKey("http://example.org/hasAge"))
        assert(expandedMap.containsKey("@type"))

        val hasName = (expandedMap["http://example.org/hasName"] as List<Map<String, String>>)[0]["@value"]
        val hasAge = (expandedMap["http://example.org/hasAge"] as List<Map<String, Int>>)[0]["@value"]
        val type = (expandedMap["@type"] as List<String>)[0]

        assertEquals("John Doe", hasName)
        assertEquals(30, hasAge)
        assertEquals("http://example.org/Person", type)
    }

    @Test
    fun encryptSimple() {
        val (randomKey, _) = generateX25519KeyPair()
        val associatedData = ByteArray(16)

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

        val a = 2
    }

    @Test
    fun encryptComplex() {
        val (randomKey, _) = generateX25519KeyPair()
        val associatedData = ByteArray(16)

        val jsonString = """
            {
              "@context": { "ex": "http://example.org/" },
              "@id": "ex:person1",
              "@type": "ex:Person",
              "ex:hasName": "John Doe",
              "ex:hasAge": "30",
              "ex:address": {
                "ex:street": "123 Main St",
                "ex:city": {
                  "ex:name": "Springfield",
                  "ex:state": "Illinois"
                }
              },
              "ex:hasChildren": [
                {
                  "@id": "ex:child1",
                  "ex:hasName": "Jane Doe",
                  "ex:hasAge": "10"
                },
                {
                  "@id": "ex:child2",
                  "ex:hasName": "Jack Doe",
                  "ex:hasAge": "7"
                }
              ]
            }
            """.trimIndent()

        val map = JsonUtils.fromString(jsonString) as Map<String, Any>
        val expandedMap = (JsonLdProcessor.expand(map)[0]) as Map<String, Any>

        val encryptedMap = RDFTransformer.encrypt(expandedMap, randomKey.encoded, associatedData, predicatesToEncrypt)

        val a = 2
    }


    @Test
    fun transformSimple() {
        val (randomKey, _) = generateX25519KeyPair()
        val associatedData = ByteArray(16)

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

        assertFalse(transformedMap.containsKey("_:B"))

        val a = 2
    }

    @Test
    fun transformComplex() {

    }


    @Test
    fun RDFEncryptionProcessorTest() {
        val (randomKey, _) = generateX25519KeyPair()
        val associatedData = ByteArray(16)

        val jsonString = """
            {
              "@context": { "ex": "http://example.org/" },
              "@id": "ex:person1",
              "@type": "ex:Person",
              "ex:hasName": "John Doe",
              "ex:hasAge": 30,
              "ex:address": {
                "@id": "address_id",
                "ex:street": "123 Main St",
                "ex:city": {
                  "@id": "city_id",
                  "ex:name": "Springfield",
                  "ex:state": "Illinois"
                }
              },
              "ex:hasChildren": [
                {
                  "@id": "ex:child1",
                  "ex:hasName": "Jane Doe",
                  "ex:hasAge": "10"
                },
                {
                  "@id": "ex:child2",
                  "ex:hasName": "Jack Doe",
                  "ex:hasAge": "7"
                }
              ],
              "ex:test": [ "test" ]
            }
            """.trimIndent()

        val map = JsonUtils.fromString(jsonString) as Map<String, Any>
        val expandedMap = (JsonLdProcessor.expand(map)[0]) as Map<String, Any>

        val encryptedMap = RDFEncryptionProcessor.encrypt(expandedMap, randomKey.encoded, associatedData, predicatesToEncrypt)

        val transformedMap = RDFEncryptionProcessor.objectTransform(encryptedMap)["transformedMap"]

        val a = 2
    }
}