package kvasir.definitions.rdf

import com.fasterxml.jackson.annotation.JsonProperty
import kvasir.definitions.rdf.KvasirVocab.baseUri

object KvasirVocab {

    const val baseUri = "https://kvasir.discover.ilabt.imec.be/vocab#"

    val context = mapOf(JsonLdKeywords.vocab to baseUri)

    const val AssertEmptyResult = "${baseUri}AssertEmptyResult"
    const val AssertNonEmptyResult = "${baseUri}AssertNonEmptyResult"
    const val S3Reference = "${baseUri}S3Reference"

    const val autoIngestRDF = "${baseUri}autoIngestRDF"
    const val assert = "${baseUri}assert"
    const val configuration = "${baseUri}configuration"
    const val defaultContext = "${baseUri}defaultContext"
    const val delete = "${baseUri}delete"
    const val description = "${baseUri}description"
    const val message = "${baseUri}message"
    const val graph = "${baseUri}graph"
    const val insert = "${baseUri}insert"
    const val key = "${baseUri}key"
    const val name = "${baseUri}name"
    const val nrOfDeletes = "${baseUri}nrOfDeletes"
    const val nrOfInserts = "${baseUri}nrOfInserts"
    const val podId = "${baseUri}podId"
    const val query = "${baseUri}query"
    const val statusCode = "${baseUri}statusCode"
    const val statusEntry = "${baseUri}statusEntry"
    const val schema = "${baseUri}schema"
    const val shacl = "${baseUri}shacl"
    const val sliceId = "${baseUri}sliceId"
    const val totalCount = "${baseUri}totalCount"
    const val targetGraphs = "${baseUri}targetGraphs"
    const val timestamp = "${baseUri}timestamp"
    const val versionId = "${baseUri}versionId"
    const val with = "${baseUri}with"
    const val authConfiguration = "${baseUri}authConfiguration"
    const val serverUrl = "${baseUri}serverUrl"
    const val clientId = "${baseUri}clientId"
    const val clientSecret = "${baseUri}clientSecret"
    const val profile = "${baseUri}profile"
    const val authServerUrl = "${baseUri}authServerUrl"
    const val supportsChanges = "${baseUri}supportChanges"
    // X3DH preKeys
    const val x3dhKeys = "${baseUri}x3dhKeys"
    const val publicX3DHKeys = "${baseUri}publicX3DHKeys"
    const val publicIdentityPreKeyEd25519 = "${baseUri}publicIdentityPreKeyEd25519"
    const val publicIdentityPreKeyX25519 = "${baseUri}publicIdentityPreKeyX25519"
    const val publicSignedPreKey = "${baseUri}publicSignedPreKey"
    const val publicOneTimePreKeys = "${baseUri}publicOneTimePreKeys"
    const val preKeySignature = "${baseUri}preKeySignature"
    // X3DH initial message
    const val initialMessage = "${baseUri}initialMessage"
    const val identityPreKey = "${baseUri}identityPreKey"
    const val ephemeralPreKey = "${baseUri}ephemeralPreKey"
    const val preKeyIdentifiers = "${baseUri}preKeyIdentifiers"
    const val initialCiphertext = "${baseUri}initialCiphertext"
    // Message handling
    const val messageInboxList = "${baseUri}messageInboxList"
    const val messageOutboxList = "${baseUri}messageOutboxList"
    const val messageInbox = "${baseUri}messageInbox"
    const val messageOutbox = "${baseUri}messageOutbox"
    const val messageId = "${baseUri}messageId"
    const val publicKey = "${baseUri}publicKey"
    const val cipherText = "${baseUri}cipherText"
    const val sequenceNumber = "${baseUri}sequenceNumber"
    const val prevSequenceNumber = "${baseUri}prevSequenceNumber"
}

object KvasirNamedGraphs {

    const val baseUri = "https://kvasir.discover.ilabt.imec.be/named-graphs#"

    const val queryResultPaginationGraph = "${baseUri}qr-pagination"
    const val queryResultDataGraph = "${baseUri}qr-data"
    const val queryResultErrorsGraph = "${baseUri}qr-errors"

}