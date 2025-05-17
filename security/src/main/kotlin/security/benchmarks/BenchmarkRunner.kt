package security.benchmarks

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.apache.jena.rdf.model.Model
import org.apache.jena.rdf.model.ModelFactory
import org.apache.jena.riot.Lang
import org.apache.jena.riot.RDFDataMgr
import org.apache.jena.riot.RDFParser
import java.io.File
import java.io.StringReader
import java.io.StringWriter


fun main() {
    val tripleCount = 250
    val authCode =
        "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwbmZCckM5OVczWEppaUI2SllzamNESWZlZWRmNXh5VHN2T3dYaUExY2E0In0.eyJleHAiOjE3NDcwODg5NTcsImlhdCI6MTc0NzA3NDU1NywiYXV0aF90aW1lIjoxNzQ3MDc0NTM2LCJqdGkiOiIxYmNiYmE1OS1kY2NkLTQ1MjktYjU3Zi1mZTAwZDFkYmE4Y2UiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgyODAvcmVhbG1zL2FsaWNlYm9iIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjEzYmIwNDQzLTdlYmUtNDEyNy05NTMwLTI5ZmUyYWI1ZDUxOCIsInR5cCI6IkJlYXJlciIsImF6cCI6InB1YmxpYy1jbGllbnQiLCJzaWQiOiIzYWEzMzY3Mi1lNmY2LTQyNTctOGI2NC03OTVmNDhkNzM5MTEiLCJhY3IiOiIxIiwiYWxsb3dlZC1vcmlnaW5zIjpbImh0dHA6Ly9sb2NhbGhvc3Q6NDIwMCJdLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsib3duZXIiLCJkZWZhdWx0LXJvbGVzLWFsaWNlYm9iIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlYm9iIERlbW8iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJhbGljZWJvYiIsImdpdmVuX25hbWUiOiJBbGljZWJvYiIsImZhbWlseV9uYW1lIjoiRGVtbyIsImVtYWlsIjoiYWxpY2Vib2JAZXhhbXBsZS5vcmcifQ.WwUQ3yWT0THCbjk-iuR9jP5Fg6Zd3HR0xWomeHmZryYvyS9sNVzirMKh86tzfBgHwSdVbMmxeXJ_-8hgJbiKnwTU-XIduWmEK1b0fdhp_TP5jjlZqYi5RlXkOR9_SUtoZwgj8bWoifiBJmO3Vtt9lSpg9RTKil8zz4Xq8UcQ5AsfLZOYrkT4IPSpe-64fS9kbi22iPGXUyZpDEc_R6Yo7oZCgoPnzko55WNJcWFDGqhyMG7mWxlPFLyO_xjP6Cz4WTzm7BBgus8oegJWbHzII8Nnfowuk2PAFNjJsLTfV5RlOezmW46fa0GERsNp0Bxbteu8d4fpsr6Csh9NbtlTgg"

    // val resultsWithoutApi = benchmarkWithoutAPI(tripleCount)

    // val resultsWithApi = benchmarkWithAPI(tripleCount, authCode)

    // val resultsSum = benchmarkSum(tripleCount, authCode)

    // val timeX3dhAvg = benchmarkX3DH(tripleCount, 10)

//    val resultsX3DH = mapOf(
//        "times" to timeX3dhAvg,
//        "averageTime" to timeX3dhAvg.average()
//    )

    val encryptionOverhead = encryptionOverheadMeasurer(tripleCount)

    val mapper = jacksonObjectMapper()
    mapper.writerWithDefaultPrettyPrinter()
        .writeValue(File("benchmark_results.json"), encryptionOverhead)

}