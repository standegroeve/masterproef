package security.benchmarks

import com.fasterxml.jackson.annotation.JsonProperty
import org.apache.jena.query.QueryExecutionFactory
import org.apache.jena.rdf.model.ModelFactory
import org.apache.jena.rdf.model.Statement
import org.apache.jena.riot.RDFDataMgr
import org.apache.jena.riot.RDFFormat
import security.partialEncrypt.RDFEncryptionProcessor
import java.io.StringReader
import java.io.StringWriter

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

fun generateJsonLdSum(tripleCount: Int): String {
    val model = ModelFactory.createDefaultModel()

    model.setNsPrefix("ex", "http://example.org/")
    model.setNsPrefix("renc", "http://www.w3.org/ns/renc#")

    for (i in 0 until tripleCount) {
        val subject = model.createResource("ex:$i")
        model.add(subject, model.createProperty("ex:name"), "Name$i")
        model.add(subject, model.createProperty("ex:number"), model.createTypedLiteral(1))

        val relatedNumber = i + tripleCount
        val relatedSubject = model.createResource("ex:$relatedNumber")

        model.add(subject, model.createProperty("ex:relatedTo"), relatedSubject)
        model.add(relatedSubject, model.createProperty("ex:name"), "Name$relatedNumber")

    }

    val out = StringWriter()
    RDFDataMgr.write(out, model, RDFFormat.JSONLD_PRETTY)
    return out.toString()
}

fun getSumOfJsonLd(jsonString: String): Int {
    val model = ModelFactory.createDefaultModel()

    model.read(StringReader(jsonString), null, "JSON-LD")

    val sumQuery = """
            PREFIX ex: <http://example.org/>
            SELECT (SUM(?num) AS ?total)
            WHERE {
                ?s ex:number ?num .
            }
        """.trimIndent()

    val queryExec = QueryExecutionFactory.create(sumQuery, model)
    val results = queryExec.execSelect()

    if (results.hasNext()) {
        return results.next().getLiteral("total").int
    }
    throw RuntimeException("No numbers found in the JsonLd")
}

fun getValuesToEncrypt(): List<String> {
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

fun getTriplesToEncrypt(tripleCount: Int): List<List<Statement>> {
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

fun printProgressBar(current: Int, total: Int, barLength: Int = 50) {
    val percent = (current.toDouble() / total * 100).toInt()
    val filledLength = (barLength * current) / total
    val bar = "█".repeat(filledLength) + "-".repeat(barLength - filledLength)
    print("\rProgress: |$bar| $percent% ($current/$total)")
    if (current == total) println()
}