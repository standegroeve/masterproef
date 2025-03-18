import com.github.jsonldjava.core.JsonLdProcessor
import com.github.jsonldjava.utils.JsonUtils
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import security.RDFTransformer
import security.crypto.generateX25519KeyPair

class transformTests() {
    @Test
    fun readAndExpand() {
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
        val hasAge = (expandedMap["http://example.org/hasAge"] as List<Map<String, String>>)[0]["@value"]
        val type = (expandedMap["@type"] as List<String>)[0]

        assertEquals("John Doe", hasName)
        assertEquals("30", hasAge)
        assertEquals("http://example.org/Person", type)
    }

    @Test
    fun encryptSimple() {
        val (randomKey, _) = generateX25519KeyPair()
        val associatedData = ByteArray(16)

        val jsonMap: Map<String, Any> = mapOf(
            "@context" to mapOf("ex" to "http://example.org/"),
            "@id" to "ex:person1",
            "@type" to "ex:Person",
            "ex:hasName" to "John Doe",
            "ex:hasAge" to "30"
        )

        val map = RDFTransformer.encrypt(jsonMap, randomKey.encoded, associatedData)

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

        val encryptedMap = RDFTransformer.encrypt(expandedMap, randomKey.encoded, associatedData)

        val a = 2
    }
}