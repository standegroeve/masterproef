package security

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.util.*

class User(val podId: String) {
    var preKeys: X3DHPreKeys? = null
    var sharedKey: ByteArray? = null
}










data class X3DHPreKeys(
    val publicIdentityPreKey: X25519PublicKeyParameters,
    val publicSignedPrekey: X25519PublicKeyParameters,
    val publicOneTimePrekeys: List<X25519PublicKeyParameters>,
    val preKeySignature: ByteArray,
    val privateIdentityPreKey: X25519PrivateKeyParameters,
    val privateSignedPrekey: X25519PrivateKeyParameters,
    val privateOneTimePrekeys: List<X25519PrivateKeyParameters>
) {
    fun getPublic(): X3DHPublicPreKeys {
        return X3DHPublicPreKeys(publicIdentityPreKey, publicSignedPrekey, publicOneTimePrekeys, preKeySignature)
    }
}

data class X3DHPublicPreKeys(
    val publicIdentityPreKey: X25519PublicKeyParameters,
    val publicSignedPrekey: X25519PublicKeyParameters,
    val publicOneTimePrekeys: List<X25519PublicKeyParameters>?,
    val preKeySignature: ByteArray
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class X3DHPublicKeysAsString(
    @JsonProperty("kss:publicIdentityPreKey") val publicIdentityPreKey: String,
    @JsonProperty("kss:publicSignedPrekey") val publicSignedPrekey: String,
    @JsonProperty("kss:publicOneTimePrekeys") val publicOneTimePrekeys: List<String>,
    @JsonProperty("kss:preKeySignature") val preKeySignature: String
) {
    fun convertToX25519(): X3DHPublicPreKeys {
        return X3DHPublicPreKeys(
            publicIdentityPreKey = X25519PublicKeyParameters(Base64.getDecoder().decode(publicIdentityPreKey)),
            publicSignedPrekey = X25519PublicKeyParameters(Base64.getDecoder().decode(publicSignedPrekey)),
            publicOneTimePrekeys = publicOneTimePrekeys.map { X25519PublicKeyParameters(Base64.getDecoder().decode(it)) },
            preKeySignature = Base64.getDecoder().decode(preKeySignature)
        )
    }
}

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