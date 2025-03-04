package kvasir.definitions.security

import com.fasterxml.jackson.annotation.JsonProperty
import kvasir.definitions.rdf.KvasirVocab

data class PublicX3DHKeys(
    @JsonProperty(KvasirVocab.publicIdentityPreKeyEd25519)
    val publicIdentityPreKeyEd25519: String,
    @JsonProperty(KvasirVocab.publicIdentityPreKeyX25519)
    val publicIdentityPreKeyX25519: String,
    @JsonProperty(KvasirVocab.publicSignedPreKey)
    val publicSignedPreKey: String,
    @JsonProperty(KvasirVocab.publicOneTimePreKeys)
    val publicOneTimePreKeys: List<String>,
    @JsonProperty(KvasirVocab.preKeySignature)
    val preKeySignature: String
)