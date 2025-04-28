package security.partialEncrypt

import com.fasterxml.jackson.annotation.JsonProperty
import org.apache.jena.datatypes.xsd.XSDDatatype
import org.apache.jena.query.QueryExecution
import org.apache.jena.query.QueryExecutionFactory
import org.apache.jena.query.QuerySolution
import org.apache.jena.query.ResultSet
import org.apache.jena.rdf.model.*
import org.apache.jena.update.UpdateAction
import security.crypto.CryptoUtils.aesGcmDecrypt
import security.crypto.CryptoUtils.aesGcmEncrypt
import java.io.StringReader
import java.io.StringWriter
import java.util.*

data class EC(
    @JsonProperty("@value") val `@value`: String,
    @JsonProperty("renc_datatype") val renc_datatype: String
) {
    override fun toString(): String {
        return "@value=$`@value`, renc_datatype=$renc_datatype"
    }

    companion object {
        // Function to parse JSON string into EC object
        fun fromCustomString(data: String): EC {
            val map = data.split(", ")
                .associate {
                    val (key, value) = it.split("=", limit = 2)
                    key to value
                }
            return EC(map["@value"] ?: "", map["renc_datatype"] ?: "")
        }
    }
}


object RDFEncryptionProcessor {

    fun encryptRDF(jsonString: String, timestampBytes: ByteArray, secretKey: ByteArray, associatedData: ByteArray, valuesToEncrypt: List<String>, tripleGroupsToEncrypt: List<List<Statement>>): String {
        val model = ModelFactory.createDefaultModel()

        model.read(StringReader(jsonString), "http://example.org/", "JSON-LD")

        //////////////////////////////////
        // Handle triple set encryption //
        //////////////////////////////////

        for (group in tripleGroupsToEncrypt) {
            val queryHelper = StringBuilder()

            group.joinToString("\n") { stmt ->
                queryHelper.append("<${stmt.subject}> <${stmt.predicate}> \"${stmt.`object`}\" .\n")
            }
            if (queryHelper.isNotEmpty()) {
                queryHelper.setLength(queryHelper.length - 1)  // Remove the last character (newline)
            }

            val valueToEncrypt = queryHelper.toString()
            val encryptedValue = aesGcmEncrypt(timestampBytes + valueToEncrypt.toByteArray(), secretKey, associatedData)

            val ECString = EC(
                `@value` = Base64.getEncoder().encodeToString(encryptedValue),
                renc_datatype = "rdf:Resource"
            ).toString()

            val blankNode = model.createResource()
            val randomUUID = UUID.randomUUID().toString()

            model.add(blankNode, model.createProperty("renc:encTriples"), model.createLiteral(ECString))
            model.add(blankNode, model.createProperty("renc:assignedURI"), randomUUID)
            model.add(group.first().subject, model.createProperty("http://www.w3.org/ns/renc#triples"), randomUUID)

            model.remove(group)
        }

        for (value in valuesToEncrypt) {

            ////////////////////////////////////////////////////////////
            // Handle predicate and the related object transformation //
            ////////////////////////////////////////////////////////////


            val selectQueryPred = """
                    PREFIX ex: <http://example.org/>
                    PREFIX renc: <http://www.w3.org/ns/renc#>
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
                val objectNode = result.get("o")

                val (objectValueString, objectDatatypeURI) = when {
                    objectNode.isLiteral -> {
                        val literal = objectNode.asLiteral()
                        val valueStr = literal.string
                        val datatype = literal.datatypeURI
                        Pair(valueStr, datatype)
                    }
                    objectNode.isResource -> {
                        val resource = objectNode.asResource()
                        val valueStr = resource.uri
                        Pair(valueStr, null)
                    }
                    else -> throw IllegalStateException("Unexpected RDF Node type for object")
                }

                val objectValue = if (objectDatatypeURI != null) {
                    "\"$objectValueString\"^^<$objectDatatypeURI>"
                } else {
                    "<$objectValueString>"
                }

                val encryptedObject = aesGcmEncrypt(timestampBytes + objectValueString.toByteArray(), secretKey, associatedData)
                val encryptedPredicate = aesGcmEncrypt(timestampBytes + value.toByteArray(), secretKey, associatedData)

                val randomReificationNumber = UUID.randomUUID()
                val blankNode = model.createResource()
                val randomUUID = UUID.randomUUID().toString()

                val updateQuery = """
                    PREFIX ex: <http://example.org/>
                    PREFIX renc: <http://www.w3.org/ns/renc#>
                    DELETE { ?s <$value> $objectValue }
                    INSERT { ?s renc:encPredicate ex:reificationQuad-$randomReificationNumber }
                    WHERE {
                        ?s <$value> $objectValue .
                    }
                """.trimIndent()

                model.add(blankNode, model.createProperty("renc:assignedURI"), randomUUID)
                model.add(blankNode, model.createProperty("renc:encNLabel"), model.createLiteral(EC(
                    `@value` = Base64.getEncoder().encodeToString(encryptedObject),
                    renc_datatype = objectDatatypeURI ?: "http://www.w3.org/2001/XMLSchema#anyURI",  // Default for resource
                ).toString()))

                val statement = model.createStatement(
                    model.createResource("http://example.org/reificationQuad-$randomReificationNumber"),
                    model.createProperty("renc:encPredicate"),
                    randomUUID
                )

                val reifiedStatement = statement.createReifiedStatement("http://example.org/reificationQuad-$randomReificationNumber")
                reifiedStatement.addProperty(model.createProperty("renc:encPLabel"), EC(
                    `@value` = Base64.getEncoder().encodeToString(encryptedPredicate),
                    renc_datatype = XSDDatatype.XSDstring.uri,
                ).toString())

                UpdateAction.parseExecute(updateQuery, model)
            }
            queryExecPred.close()

            ///////////////////////////////
            // Handle object uri's alone //
            ///////////////////////////////

            val selectQueryObj = """
                    PREFIX ex: <http://example.org/>
                    PREFIX renc: <http://www.w3.org/ns/renc#>
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

            val encryptedObject = aesGcmEncrypt(timestampBytes + value.toByteArray(), secretKey, associatedData)

            for (result in resultsListObj) {
                val subjectValue = result.getResource("s")
                val predicateValue = result.getResource("p")

                val blankNode = model.createResource()
                val randomUUID = UUID.randomUUID().toString()

                val updateQuery = """
                        PREFIX ex: <http://example.org/>
                        PREFIX renc: <http://www.w3.org/ns/renc#>
                        DELETE { <$subjectValue> <$predicateValue> "$value" }
                        INSERT { <$subjectValue> <$predicateValue> "$blankNode" }
                        WHERE {
                            <$subjectValue> <$predicateValue> "$value" .
                        }
                    """.trimIndent()

                model.add(blankNode, model.createProperty("renc:assignedURI"), randomUUID)
                model.add(blankNode, model.createProperty("renc:encNLabel"), model.createLiteral(EC(
                    `@value` = Base64.getEncoder().encodeToString(encryptedObject),
                    renc_datatype = XSDDatatype.XSDstring.uri
                ).toString()))

                UpdateAction.parseExecute(updateQuery, model)
            }

            queryExecObj.close()

            ////////////////////////////////////
            // Handle subject transformations //
            ////////////////////////////////////

            val subjectRes = model.getResource(value)

            val resultsListSubj = model.listStatements(subjectRes, null as Property?, null as RDFNode?).toList()

            /*
                Get triples in Turtle form
            */
            val turtleBuilder = StringBuilder()

            resultsListSubj.joinToString("\n") { stmt ->
                turtleBuilder.append("<${stmt.subject}> <${stmt.predicate}> \"${stmt.`object`}\" .\n")
            }
            if (turtleBuilder.isNotEmpty()) {
                turtleBuilder.setLength(turtleBuilder.length - 1)  // Remove the last character (newline)
            }

            val turtleString = turtleBuilder.toString()


            if (turtleString.isNotEmpty()) {
                val encryptedSubject = aesGcmEncrypt(timestampBytes + turtleString.toByteArray(), secretKey, associatedData)

                // Remove triples with old subject value
                model.remove(resultsListSubj)

                val blankNode = model.createResource()
                val randomUUID = UUID.randomUUID().toString()

                model.add(blankNode, model.createProperty("renc:assignedURI"), randomUUID)
                model.add(blankNode, model.createProperty("renc:encNLabel"), model.createLiteral(
                        EC(
                            `@value` = Base64.getEncoder().encodeToString(encryptedSubject),
                            renc_datatype = "rdf:Resource"
                        ).toString()
                    )
                )

                val selectQuerySubjAsObj = """
                        PREFIX ex: <http://example.org/>
                        PREFIX renc: <http://www.w3.org/ns/renc#>
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
                            PREFIX ex: <http://example.org/>
                            PREFIX renc: <http://www.w3.org/ns/renc#>
                            DELETE { <$subjectValue> <$predicateValue> <$value> }
                            INSERT { <$subjectValue> <$predicateValue> "$randomUUID" }
                            WHERE {
                                <$subjectValue> <$predicateValue> <$value> .
                            }
                        """.trimIndent()

                    UpdateAction.parseExecute(updateQuery, model)
                }

                queryExecSubjAsObj.close()
            }
        }

        val writer = StringWriter()
        model.write(writer, "JSON-LD")
        return writer.toString()
    }








    fun decryptRDF(jsonString: String, secretKey: ByteArray, associatedData: ByteArray): Pair<String, Long> {
        val model = ModelFactory.createDefaultModel()

        var timestampBytes: Long? = null

        model.read(StringReader(jsonString), null, "JSON-LD")

        ///////////////////////////
        // Handle renc:Predicate //
        ///////////////////////////

        val selectQueryPred = """
                    PREFIX ex: <http://example.org/>
                    PREFIX renc: <http://www.w3.org/ns/renc#>
                    SELECT ?s ?o
                    WHERE {
                        ?s renc:encPredicate ?o .
                    }
                """.trimIndent()

        val queryExecPred: QueryExecution = QueryExecutionFactory.create(selectQueryPred, model)
        val resultsPred: ResultSet = queryExecPred.execSelect()

        val resultsListPred = mutableListOf<QuerySolution>()
        while (resultsPred.hasNext()) {
            resultsListPred.add(resultsPred.nextSolution())
        }

        for (result in resultsListPred) {
            val subjectValue = result.getResource("s")
            val objectValue = result.get("o") as Resource

            val newObject = model.listStatements(objectValue, model.createProperty("http://www.w3.org/1999/02/22-rdf-syntax-ns#object"), null as RDFNode?).toList().first().`object`
            val encPLabel = model.listStatements(objectValue, model.createProperty("http://www.w3.org/ns/renc#encPLabel"), null as RDFNode?).toList().first().`object`

            val toDecrypt = EC.fromCustomString(encPLabel.toString())
            val base64Decoded = Base64.getDecoder().decode(toDecrypt.`@value`)

            val decryptedValue =  aesGcmDecrypt(base64Decoded, secretKey, associatedData)
            val decryptedString = String(decryptedValue!!.copyOfRange(8, decryptedValue.size))

            if (timestampBytes == null) timestampBytes = decryptedValue.copyOfRange(0, 8).fold(0L) { acc, byte ->
                (acc shl 8) or (byte.toLong() and 0xFF)
            }

            val updateQuery = """
                        PREFIX ex: <http://example.org/>
                        PREFIX renc: <http://www.w3.org/ns/renc#>
                        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
                        DELETE { ?s renc:encPredicate <$objectValue> }
                        INSERT { ?s <$decryptedString> "$newObject" }
                        WHERE {
                            ?s renc:encPredicate <$objectValue> .
                        }
                    """.trimIndent()

            UpdateAction.parseExecute(updateQuery, model)

            val statements = model.listStatements(objectValue, null as Property?, null as RDFNode?)
            model.remove(statements)

        }


        ///////////////////////////
        // Handle renc:encNLabel //
        ///////////////////////////

        val selectQueryObj = """
                    PREFIX ex: <http://example.org/>
                    PREFIX renc: <http://www.w3.org/ns/renc#>
                    SELECT ?s ?o
                    WHERE {
                        ?s renc:encNLabel ?o .
                    }
                """.trimIndent()

        val queryExecObj: QueryExecution = QueryExecutionFactory.create(selectQueryObj, model)
        val resultsObj: ResultSet = queryExecObj.execSelect()

        val resultsListObj = mutableListOf<QuerySolution>()
        while (resultsObj.hasNext()) {
            resultsListObj.add(resultsObj.nextSolution())
        }

        for (result in resultsListObj) {
            val subjectValue = result.getResource("s")
            val objectValue = result.getLiteral("o").string

            val toDecrypt = EC.fromCustomString(objectValue)
            val base64Decoded = Base64.getDecoder().decode(toDecrypt.`@value`)

            val decryptedValue =  aesGcmDecrypt(base64Decoded, secretKey, associatedData)

            val decryptedString = String(decryptedValue!!.copyOfRange(8, decryptedValue.size))

            if (timestampBytes == null) timestampBytes = decryptedValue.copyOfRange(0, 8).fold(0L) { acc, byte ->
                (acc shl 8) or (byte.toLong() and 0xFF)
            }

            val renc_datatype = toDecrypt.renc_datatype

            var newObject: Any?
            if (renc_datatype == "rdf:Resource") {
                val parserModel = ModelFactory.createDefaultModel()
                parserModel.setNsPrefixes(model.nsPrefixMap)
                parserModel.read(StringReader(decryptedString), "http://example.org/", "Turtle")
                model.add(parserModel)

                newObject = parserModel.shortForm(parserModel.listStatements().nextStatement().subject.uri)
            }
            else if (renc_datatype == XSDDatatype.XSDstring.uri) {
                newObject = "\"$decryptedString\""
            }
            else {
                newObject = "\"$decryptedString\"^^<$renc_datatype>"
            }

            val blankNodeUUID = model.listStatements(subjectValue, model.createProperty("http://www.w3.org/ns/renc#assignedURI"), null as RDFNode?).toList().first().`object`

            model.removeAll(subjectValue, null, null)
            val updateQuery = """
                        PREFIX ex: <http://example.org/>
                        PREFIX renc: <http://www.w3.org/ns/renc#>
                        DELETE { ?s ?p "$blankNodeUUID" }
                        INSERT { ?s ?p $newObject }
                        WHERE {
                            ?s ?p "$blankNodeUUID" .
                        }
                    """.trimIndent()

            UpdateAction.parseExecute(updateQuery, model)

            val a = 1
        }

        ////////////////////////////
        // Handle renc:encTriples //
        ////////////////////////////


        val selectQueryEncTriples = """
                    PREFIX ex: <http://example.org/>
                    PREFIX renc: <http://www.w3.org/ns/renc#>
                    SELECT ?s ?o
                    WHERE {
                        ?s renc:encTriples ?o .
                    }
                """.trimIndent()

        val queryExecEncTriples: QueryExecution = QueryExecutionFactory.create(selectQueryEncTriples, model)
        val resultsEncTriples: ResultSet = queryExecEncTriples.execSelect()

        val resultsListEncTriples = mutableListOf<QuerySolution>()
        while (resultsEncTriples.hasNext()) {
            resultsListEncTriples.add(resultsEncTriples.nextSolution())
        }

        for (result in resultsListEncTriples) {
            val subjectValue = result.getResource("s")
            val objectValue = result.getLiteral("o")

            val toDecrypt = EC.fromCustomString(objectValue.string)
            val base64Decoded = Base64.getDecoder().decode(toDecrypt.`@value`)

            val decryptedValue =  aesGcmDecrypt(base64Decoded, secretKey, associatedData)

            val decryptedString = String(decryptedValue!!.copyOfRange(8, decryptedValue.size))

            if (timestampBytes == null) timestampBytes = decryptedValue.copyOfRange(0, 8).fold(0L) { acc, byte ->
                (acc shl 8) or (byte.toLong() and 0xFF)
            }


            val parserModel = ModelFactory.createDefaultModel()
            parserModel.read(StringReader(decryptedString), "http://example.org/", "Turtle")
            model.add(parserModel)

            val triplesToAdd = parserModel.listStatements().toList()

            model.add(triplesToAdd)

            val blankNodeUUID = model.listStatements(subjectValue, model.createProperty("http://www.w3.org/ns/renc#assignedURI"), null as RDFNode?).toList().first().`object`
            model.removeAll(subjectValue, null as Property?, null as RDFNode?)


            val deleteQueryTriples = """
                    PREFIX ex: <http://example.org/>
                    PREFIX renc: <http://www.w3.org/ns/renc#>
                    DELETE {
                        ?s renc:triples "$blankNodeUUID" .
                    }
                    WHERE {
                        ?s renc:triples "$blankNodeUUID" .
                    }
                """.trimIndent()

            UpdateAction.parseExecute(deleteQueryTriples, model)
        }

        val writer = StringWriter()
        model.write(writer, "JSON-LD")
        return Pair(writer.toString(), timestampBytes!!)
    }

}