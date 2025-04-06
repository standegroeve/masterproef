package security.partialEncrypt

import org.apache.jena.datatypes.xsd.XSDDatatype
import org.apache.jena.query.*
import org.apache.jena.rdf.model.ModelFactory
import org.apache.jena.rdf.model.Property
import org.apache.jena.rdf.model.RDFNode
import org.apache.jena.rdf.model.Statement
import org.apache.jena.update.UpdateAction
import security.crypto.aesGcmEncrypt
import java.io.StringReader
import java.io.StringWriter
import java.security.MessageDigest
import java.util.*

data class EC(
    val `@value`: String,
    val renc_datatype: String,
    // val renc_hash: String
) {
    override fun toString(): String {
        return  "@value=$`@value`, renc_datatype=$renc_datatype"
    }
}


object RDFEncryptionProcessor {

    private fun sha256Hash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(input.toByteArray())
        return Base64.getEncoder().encodeToString(hashBytes) // Encode as Base64 for readability
    }

    val model = ModelFactory.createDefaultModel()


    fun encryptRDF(jsonString: String, secretKey: ByteArray, associatedData: ByteArray, valuesToEncrypt: List<String>, tripleGroupsToEncrypt: List<List<Statement>>): String {
        model.read(StringReader(jsonString), null, "JSON-LD")

        var currentChar = 'A'
        var currentReificationNumber = 1

        for (value in valuesToEncrypt) {

            ////////////////////////////////////////////////////////////
            // Handle predicate and the related object transformation //
            ////////////////////////////////////////////////////////////


            val selectQueryPred = """
                    PREFIX ex: <https://example.org/>
                    PREFIX renc: <https://www.w3.org/ns/renc#>
                    SELECT ?o
                    WHERE {
                        ?s <$value> ?o .
                    }
                """.trimIndent()

            val queryExecPred: QueryExecution = QueryExecutionFactory.create(selectQueryPred, model)
            val resultsPred: ResultSet = queryExecPred.execSelect()

            val resultsListPred = mutableListOf<QuerySolution>()
            while (resultsPred.hasNext()) {
                resultsListPred.add(resultsPred.nextSolution())
            }

            for (result in resultsListPred) {
                val objectValue = result.getLiteral("o").string

                val encryptedObject = aesGcmEncrypt(objectValue.toString().toByteArray(), secretKey, associatedData)

                val encryptedPredicate = aesGcmEncrypt(value.toString().toByteArray(), secretKey, associatedData)


                val updateQuery = """
                        PREFIX ex: <https://example.org/>
                        PREFIX renc: <https://www.w3.org/ns/renc#>
                        DELETE { ?s <$value> "$objectValue" }
                        INSERT { ?s <$value> "ex:reificationQuad$currentReificationNumber" }

                        WHERE {
                            ?s <$value> "$objectValue" .
                        }
                    """.trimIndent()

                model.add(model.createResource("_:$currentChar"), model.createProperty("renc:encNLabel"), model.createLiteral(EC(
                    `@value` = Base64.getEncoder().encodeToString(encryptedObject),
                    renc_datatype = result.getLiteral("o").datatype.uri,
                ).toString()))

                val statement = model.createStatement(
                    model.createResource("ex:reificationQuad$currentReificationNumber"),
                    model.createProperty("renc:encPredicate"),
                    model.createLiteral("_:$currentChar")
                )

                val reifiedStatement = statement.createReifiedStatement("ex:reificationQuad$currentReificationNumber")
                reifiedStatement.addProperty(model.createProperty("renc:encPLabel"), EC(
                    `@value` = Base64.getEncoder().encodeToString(encryptedPredicate),
                    renc_datatype = XSDDatatype.XSDstring.uri,
                ).toString())

                currentChar++
                currentReificationNumber++

                UpdateAction.parseExecute(updateQuery, model)
            }
            queryExecPred.close()

            ///////////////////////////////
            // Handle object uri's alone //
            ///////////////////////////////

            val selectQueryObj = """
                    PREFIX ex: <https://example.org/>
                    PREFIX renc: <https://www.w3.org/ns/renc#>
                    SELECT ?s ?p
                    WHERE {
                        ?s ?p "$value" .
                    }
                """.trimIndent()

            val queryExecObj: QueryExecution = QueryExecutionFactory.create(selectQueryObj, model)
            val resultsObj: ResultSet = queryExecObj.execSelect()

            val resultsListObj = mutableListOf<QuerySolution>()
            while (resultsObj.hasNext()) {
                resultsListObj.add(resultsObj.nextSolution())
            }

            val encryptedObject = aesGcmEncrypt(value.toString().toByteArray(), secretKey, associatedData)

            for (result in resultsListObj) {
                val subjectValue = result.getResource("s")
                val predicateValue = result.getResource("p")

                val updateQuery = """
                        PREFIX ex: <https://example.org/>
                        PREFIX renc: <https://www.w3.org/ns/renc#>
                        DELETE { <$subjectValue> <$predicateValue> "$value" }
                        INSERT { <$subjectValue> <$predicateValue> "_:$currentChar" }
                        WHERE {
                            <$subjectValue> <$predicateValue> "$value" .
                        }
                    """.trimIndent()

                model.add(model.createResource("_:$currentChar"), model.createProperty("renc:encNLabel"), model.createLiteral(EC(
                    `@value` = Base64.getEncoder().encodeToString(encryptedObject),
                    renc_datatype = XSDDatatype.XSDstring.uri
                ).toString()))


                UpdateAction.parseExecute(updateQuery, model)
            }

            if (!resultsListObj.isEmpty()) currentChar++

            queryExecObj.close()

            ////////////////////////////////////
            // Handle subject transformations //
            ////////////////////////////////////

            val subjectRes = model.getResource(value)

            val resultsListSubj = model.listStatements(subjectRes, null as Property?, null as RDFNode?).toList()

            val encryptedSubject = aesGcmEncrypt(resultsListSubj.toString().toByteArray(), secretKey, associatedData)
            val encryptedSubjectString = Base64.getEncoder().encodeToString(encryptedSubject)

            // Remove triples with old subject value
            model.remove(resultsListSubj)

            model.add(model.createResource("_:$currentChar"), model.createProperty("renc:encNLabel"), model.createLiteral(EC(
                `@value` = encryptedSubjectString,
                renc_datatype = XSDDatatype.XSDstring.uri
            ).toString()))

            val selectQuerySubjAsObj = """
                    PREFIX ex: <https://example.org/>
                    PREFIX renc: <https://www.w3.org/ns/renc#>
                    SELECT ?s ?p
                    WHERE {
                        ?s ?p <$value> .
                    }
                """.trimIndent()

            val queryExecSubjAsObj: QueryExecution = QueryExecutionFactory.create(selectQuerySubjAsObj, model)
            val resultsSubjAsObj: ResultSet = queryExecSubjAsObj.execSelect()

            val resultsListSubjAsObj = mutableListOf<QuerySolution>()
            while (resultsSubjAsObj.hasNext()) {
                resultsListSubjAsObj.add(resultsSubjAsObj.nextSolution())
            }

            for (result in resultsListSubjAsObj) {
                val subjectValue = result.getResource("s")
                val predicateValue = result.getResource("p")

                val updateQuery = """
                        PREFIX ex: <https://example.org/>
                        PREFIX renc: <https://www.w3.org/ns/renc#>
                        DELETE { <$subjectValue> <$predicateValue> <$value> }
                        INSERT { <$subjectValue> <$predicateValue> "_:$currentChar" }
                        WHERE {
                            <$subjectValue> <$predicateValue> <$value> .
                        }
                    """.trimIndent()

                UpdateAction.parseExecute(updateQuery, model)
            }

            queryExecSubjAsObj.close()


        }

        for (group in tripleGroupsToEncrypt) {
            val queryHelper = StringBuilder()

            group.joinToString("\n") { stmt ->
                queryHelper.append("<${stmt.subject}> <${stmt.predicate}> \"${stmt.`object`}\" .\n")
            }

            val valueToEncrypt = queryHelper.toString()
            val encryptedValue = aesGcmEncrypt(valueToEncrypt.toByteArray(), secretKey, associatedData)
            val encryptedValueString = Base64.getEncoder().encodeToString(encryptedValue)
            val ECString = EC(
                `@value` = encryptedValueString,
                renc_datatype = XSDDatatype.XSDstring.uri
            ).toString()

            val updateQuery = """
                    PREFIX ex: <https://example.org/>
                    PREFIX renc: <https://www.w3.org/ns/renc#>
                    DELETE {
                        $queryHelper
                    }
                    INSERT {
                        <_:$currentChar> <renc:encTriples> "$ECString"
                    }
                    WHERE {
                        $queryHelper
                    }
                """.trimIndent()

            currentChar++

            UpdateAction.parseExecute(updateQuery, model)
        }


        //model.write(System.out, "TTL") // Debug print statement

        val writer = StringWriter()
        model.write(writer, "JSON-LD")
        return writer.toString()
    }

    fun decryptRDF(jsonString: String, secretKey: ByteArray, associatedData: ByteArray) {
        model.read(StringReader(jsonString), null, "JSON-LD")

        ///////////////////////////
        // Handle renc:encNLabel //
        ///////////////////////////




        ///////////////////////////
        // Handle renc:Predicate //
        ///////////////////////////





        ////////////////////////////
        // Handle renc:encTriples //
        ////////////////////////////



    }

}