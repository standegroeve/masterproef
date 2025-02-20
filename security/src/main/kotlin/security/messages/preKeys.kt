package security.messages

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.util.*

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