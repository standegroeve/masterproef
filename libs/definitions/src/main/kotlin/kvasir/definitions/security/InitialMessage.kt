package kvasir.definitions.security

import com.fasterxml.jackson.annotation.JsonProperty
import kvasir.definitions.rdf.KvasirVocab

data class InitialMessage(
    @JsonProperty(KvasirVocab.identityPreKey)
    val identityPreKey: String,
    @JsonProperty(KvasirVocab.ephemeralPreKey)
    val ephemeralPreKey: String,
    @JsonProperty(KvasirVocab.preKeyIdentifiers)
    val preKeyIdentifiers: List<String>,
    @JsonProperty(KvasirVocab.initialCiphertext)
    val initialCiphertext: String
)