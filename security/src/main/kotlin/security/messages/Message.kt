package security.messages

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.util.*

data class EncryptedMessage(
    val messageId: Int,
    val publicKey: ByteArray,
    val cipherText: ByteArray,
    val N: Int,
    val PN: Int
)

data class EncryptedMessageString(
    @JsonProperty("kss:messageId") val messageId: String,
    @JsonProperty("kss:publicKey") val publicKey: String,
    @JsonProperty("kss:cipherText") val cipherText: String,
    @JsonProperty("kss:sequenceNumber") val N: String,
    @JsonProperty("kss:prevSequenceNumber") val PN: String
) {
    fun convertToEncryptedMessage(): EncryptedMessage {
        val objectMapper = jacksonObjectMapper()
        return EncryptedMessage(
            messageId = messageId.toInt(),
            publicKey = Base64.getDecoder().decode(publicKey),
            cipherText = Base64.getDecoder().decode(cipherText),
            N = N.toInt(),
            PN = PN.toInt()
        )
    }
}

data class DecryptedMessage(
    val messageId: Int,
    val publicKey: ByteArray,
    val plainText: String
)
