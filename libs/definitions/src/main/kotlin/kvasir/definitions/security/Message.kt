package kvasir.definitions.security

import com.fasterxml.jackson.annotation.JsonProperty
import kvasir.definitions.rdf.KvasirVocab

data class EncryptedMessage(
    @JsonProperty(KvasirVocab.messageId)
    val messageId: String,
    @JsonProperty(KvasirVocab.publicKey)
    val publicKey: String,
    @JsonProperty(KvasirVocab.cipherText)
    val cipherText: String,
    @JsonProperty(KvasirVocab.sequenceNumber)
    val sequenceNumber: String,
    @JsonProperty(KvasirVocab.prevSequenceNumber)
    val prevSequenceNumber: String
)

data class MessageStorage(
    @JsonProperty(KvasirVocab.messageInbox)
    val messageInbox: List<EncryptedMessage>,
    @JsonProperty(KvasirVocab.messageOutbox)
    val messageOutbox: List<EncryptedMessage>
)