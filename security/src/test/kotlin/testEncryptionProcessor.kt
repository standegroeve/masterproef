import org.apache.jena.rdf.model.ModelFactory
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import security.crypto.KeyUtils.generateX25519KeyPair
import security.partialEncrypt.RDFEncryptionProcessor
import java.io.StringReader


@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class testEncryptionProcessor() {

    val valuesToEncryptModel = ModelFactory.createDefaultModel()
    val groupsToEncryptModel = ModelFactory.createDefaultModel()

    val randomKey = generateX25519KeyPair().first
    val associatedData = ByteArray(16)
    val timestampBytes = ByteArray(8)


    @BeforeAll
    fun setup() {


        val valuesToEncryptJsonString = """
            {
                "@context": {
                    "ex": "http://example.org/",
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "renc": "http://www.w3.org/ns/renc#"
                },
                "@id": "ex:encryptionValues",
                "ex:valuesToEncrypt": [
                    { "@id": "ex:hasName" },
                    { "@id": "ex:hasAge" },
                    { "@id": "ex:test2" }
                ]
            }
            """.trimIndent()

        val tripleGroupsToEncryptString = """
            {
                "@context": {
                    "ex": "http://example.org/",
                    "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                    "renc": "http://www.w3.org/ns/renc#"
                },
                "@graph": [
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

        valuesToEncryptModel.read(StringReader(valuesToEncryptJsonString), null, "JSON-LD")
        groupsToEncryptModel.read(StringReader(tripleGroupsToEncryptString), null, "JSON-LD")
    }


    @Test
    fun testEncryptRDF() {

        val jsonString = """
            {
              "@context": {
                "ex": "http://example.org/",
                "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                "renc": "http://www.w3.org/ns/renc#"
              },
              "@id": "ex:person1",
              "@type": "ex:Person",
              "ex:hasName": "John Doe",
              "ex:hasAge": 30,
              "ex:address": {
                "@id": "ex:address_id",
                "ex:street": "123 Main St",
                "ex:city": {
                  "@id": "ex:city_id",
                  "ex:name": "Springfield",
                  "ex:state": "Illinois",
                   "ex:aaaa": "ex:test2"
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
              "ex:test": [ "test2", "testfdsqfdf" ]
            }
            """.trimIndent()

        val encryptionConfigRes = valuesToEncryptModel.getResource("http://example.org/encryptionValues")
        val propertyToEncrypt = valuesToEncryptModel.getProperty("http://example.org/valuesToEncrypt")

        val valuesToEncryptList = valuesToEncryptModel.listObjectsOfProperty(encryptionConfigRes, propertyToEncrypt)
            .toList()
            .map { it.asResource().uri }



        val tripleGroupsToEncrypt = groupsToEncryptModel.listStatements().toList()
            .groupBy { it.subject }
            .values.toList()


        val result = RDFEncryptionProcessor.encryptRDF(jsonString, timestampBytes, randomKey.encoded, associatedData, valuesToEncryptList, tripleGroupsToEncrypt)

        val a = 2
    }

    @Test
    fun testDecryptRDF() {
        val jsonString = """
            {
              "@context": {
                "ex": "http://example.org/",
                "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
                "renc": "http://www.w3.org/ns/renc#"
              },
              "@id": "ex:person1",
              "@type": "ex:Person",
              "ex:hasName": "John Doe",
              "ex:hasAge": 30,
              "ex:address": {
                "@id": "ex:address_id",
                "ex:street": "123 Main St",
                "ex:city": {
                  "@id": "ex:city_id",
                  "ex:name": "Springfield",
                  "ex:state": "Illinois",
                   "ex:aaaa": "ex:test2"
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
              "ex:test": [ "ex:test2", "testfdsqfdf" ]
            }
            """.trimIndent()

        val encryptionConfigRes = valuesToEncryptModel.getResource("http://example.org/encryptionValues")
        val propertyToEncrypt = valuesToEncryptModel.getProperty("http://example.org/valuesToEncrypt")

        val valuesToEncryptList = valuesToEncryptModel.listObjectsOfProperty(encryptionConfigRes, propertyToEncrypt)
            .toList()
            .map { it.asResource().uri }



        val tripleGroupsToEncrypt = groupsToEncryptModel.listStatements().toList()
            .groupBy { it.subject }
            .values.toList()


        val toDecrypt = RDFEncryptionProcessor.encryptRDF(jsonString, timestampBytes, randomKey.encoded, associatedData, valuesToEncryptList, tripleGroupsToEncrypt)

        println(toDecrypt)

        println(RDFEncryptionProcessor.decryptRDF(toDecrypt, randomKey.encoded, associatedData).first)
    }

}