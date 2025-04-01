package partialEncrypt

import com.github.jsonldjava.core.JsonLdProcessor
import com.github.jsonldjava.utils.JsonUtils
import security.partialEncrypt.RDFTransformer
import kotlin.test.Test


class testObjectTransform {
    val randomKey = security.crypto.generateX25519KeyPair().first
    val associatedData = ByteArray(16)

    val predicatesToEncrypt = listOf(
        "http://example.org/hasName",
        "http://example.org/hasAge",
        "http://example.org/hasAddress",
        "http://example.org/hasCity",
        "http://example.org/street"
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
        val transformedMap = RDFTransformer.objectTransform(jsonMap = encryptedMap).first

        assert(transformedMap.size == 6)

        assert(transformedMap.containsKey("_:A"))
        assert(transformedMap.containsKey("_:B"))
        assert(!transformedMap.containsKey("_:C"))

        assert((transformedMap["_:A"] as Map<String, Any>)["renc:encNLabel"] is String)
        assert((transformedMap["_:B"] as Map<String, Any>)["renc:encNLabel"] is String)
    }

    @Test
    fun objectDuplicateTransform() {
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
        val transformedMap = RDFTransformer.objectTransform(jsonMap = encryptedMap).first

        assert(transformedMap.size == 5)

        assert(transformedMap.containsKey("_:A"))
        assert(!transformedMap.containsKey("_:B"))
    }

    @Test
    fun objectNestedTransform() {
        val jsonString = """
            {
                "@context": { "ex": "http://example.org/" },
                "@id": "ex:person1",
                "@type": "ex:Person",
                "ex:hasAddress": {
                    "ex:hasCity": {
                        "ex:street": "123 Main St"
                    }
                }
            }
            """.trimIndent()

        val map = JsonUtils.fromString(jsonString) as Map<String, Any>
        val expandedMap = (JsonLdProcessor.expand(map)[0]) as Map<String, Any>
        val encryptedMap = RDFTransformer.encrypt(expandedMap, randomKey.encoded, associatedData, predicatesToEncrypt)
        val transformedMap = RDFTransformer.objectTransform(jsonMap = encryptedMap).first

        assert(transformedMap.size == 4)

        assert(transformedMap.containsKey("_:A"))
        assert(!transformedMap.containsKey("_:B"))

        transformedMap.keys.remove("_:A")
        transformedMap.keys.remove("@id")
        transformedMap.keys.remove("@type")
        val key = transformedMap.keys.first()

        assert((((transformedMap[key] as Map<String, Any>).values.first() as Map<String, Any>).values.first() as Map<String, Any>).values.first().equals("_:A"))

    }

    @Test
    fun objectNestedDuplicateObjects() {
        val jsonString = """{
            "@context": { "ex": "http://example.org/" },
            "@id": "ex:person1",
            "@type": "ex:Person",
            "ex:hasName": "John Doe",
            "ex:hasAge": 30,
            "ex:hasAddress": {
            "ex:hasCity": {
            "ex:street": "123 Main St"
        }
        },
            "ex:hasAddressDuplicate": {
                "ex:hasCity": {
                    "ex:street": "123 Main St"
            }
        },
            "ex:hasContact": {
            "ex:email": "john.doe@example.com",
            "ex:phoneNumbers": [
            { "ex:type": "home", "ex:number": "+1-555-1234" },
            { "ex:type": "work", "ex:number": "+1-555-5678" }
            ]
        },
            "ex:hasChildren": [
            {
                "@id": "ex:child1",
                "ex:hasName": "Jane Doe"
            }
            ],
            "ex:hasHobbies": ["Reading", "Gaming"]
        }
        """.trimIndent()

        val map = JsonUtils.fromString(jsonString) as Map<String, Any>
        val expandedMap = (JsonLdProcessor.expand(map)[0]) as Map<String, Any>
        val encryptedMap = RDFTransformer.encrypt(expandedMap, randomKey.encoded, associatedData, predicatesToEncrypt)
        val transformedMap = RDFTransformer.objectTransform(jsonMap = encryptedMap).first

        val a = 2
    }

    @Test
    fun objectTransformPartialEncryption() {
        val predicatesToEncryptEmpty = emptyList<String>()

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
        val encryptedMap = RDFTransformer.encrypt(expandedMap, randomKey.encoded, associatedData, predicatesToEncryptEmpty)
        val transformedMap = RDFTransformer.objectTransform(jsonMap = encryptedMap).first


        assert((transformedMap["@id"]!! as String).contains("person1"))
        assert((transformedMap["@type"]!! as String).contains("Person"))
        assert(transformedMap["http://example.org/hasName"]!!.equals("John Doe"))
        assert(transformedMap["http://example.org/hasAge"]!!.equals(30))

        val predicatesToEncryptPartial = listOf(
            "http://example.org/hasName"
        )

        val encryptedPartial = RDFTransformer.encrypt(expandedMap, randomKey.encoded, associatedData, predicatesToEncryptPartial)
        val transformedPartial = RDFTransformer.objectTransform(jsonMap = encryptedPartial).first

        assert((transformedPartial["@id"]!! as String).contains("person1"))
        assert((transformedPartial["@type"]!! as String).contains("Person"))
        assert(!transformedPartial.containsKey("http://example.org/hasName"))
        assert(transformedPartial["http://example.org/hasAge"]!!.equals(30))

        val a = 2
    }
}