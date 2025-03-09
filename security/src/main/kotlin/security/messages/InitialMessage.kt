package security.messages

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.util.*

data class InitialMessage(
    val identityPreKey: X25519PublicKeyParameters,
    val ephemeralPreKey: X25519PublicKeyParameters,
    val preKeyIdentifiers: Int,
    val initialCiphertext: ByteArray
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class InitialMessageString(
    @JsonProperty("kss_identityPreKey") val identityPreKey: String,
    @JsonProperty("kss_ephemeralPreKey") val ephemeralPreKey: String,
    @JsonProperty("kss_preKeyIdentifiers") val preKeyIdentifiers: String,
    @JsonProperty("kss_initialCiphertext") val initialCiphertext: String
) {
    fun toX25519(): InitialMessage {
        return  InitialMessage(
            identityPreKey = X25519PublicKeyParameters(Base64.getDecoder().decode(identityPreKey)),
            ephemeralPreKey = X25519PublicKeyParameters(Base64.getDecoder().decode(ephemeralPreKey)),
            preKeyIdentifiers = preKeyIdentifiers.toInt(),
            initialCiphertext = Base64.getDecoder().decode(initialCiphertext)
        )
    }
}