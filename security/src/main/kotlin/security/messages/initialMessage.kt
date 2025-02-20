package security.messages

import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.util.*

data class Bericht(
    val identityPreKey: X25519PublicKeyParameters,
    val ephemeralPreKey: X25519PublicKeyParameters,
    val preKeyIdentifiers: List<Int>,
    val ciphertext: ByteArray
)

data class BerichtAsString(
    val identityPreKey: String,
    val ephemeralPreKey: String,
    val preKeyIdentifiers: List<Int>,
    val ciphertext: String
) {
    fun toX25519(): Bericht {
        return  Bericht(
            identityPreKey = X25519PublicKeyParameters(Base64.getDecoder().decode(identityPreKey)),
            ephemeralPreKey = X25519PublicKeyParameters(Base64.getDecoder().decode(ephemeralPreKey)),
            preKeyIdentifiers = preKeyIdentifiers,
            ciphertext = Base64.getDecoder().decode(ciphertext)
        )
    }
}