package security.messages

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
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
        val privateEd25519 = Ed25519PrivateKeyParameters(privateIdentityPreKey.encoded, 0)
        return X3DHPublicPreKeys(privateEd25519.generatePublicKey(), publicIdentityPreKey, publicSignedPrekey, publicOneTimePrekeys, preKeySignature)
    }
}

data class X3DHPublicPreKeys(
    val publicIdentityPreKeyEd25519: Ed25519PublicKeyParameters,
    val publicIdentityPreKeyX25519: X25519PublicKeyParameters,
    val publicSignedPreKey: X25519PublicKeyParameters,
    val publicOneTimePreKeys: List<X25519PublicKeyParameters>?,
    val preKeySignature: ByteArray
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class X3DHPublicKeysAsString(
    @JsonProperty("kss:publicIdentityPreKeyEd25519") val publicIdentityPreKeyEd25519: String,
    @JsonProperty("kss:publicIdentityPreKeyX25519") val publicIdentityPreKeyX25519: String,
    @JsonProperty("kss:publicSignedPreKey") val publicSignedPreKey: String,
    @JsonProperty("kss:publicOneTimePreKeys") val publicOneTimePreKeys: List<String>,
    @JsonProperty("kss:preKeySignature") val preKeySignature: String
) {
    fun convertToX25519(): X3DHPublicPreKeys {
        return X3DHPublicPreKeys(
            publicIdentityPreKeyEd25519 = Ed25519PublicKeyParameters(Base64.getDecoder().decode(publicIdentityPreKeyEd25519)),
            publicIdentityPreKeyX25519 = X25519PublicKeyParameters(Base64.getDecoder().decode(publicIdentityPreKeyX25519)),
            publicSignedPreKey = X25519PublicKeyParameters(Base64.getDecoder().decode(publicSignedPreKey)),
            publicOneTimePreKeys = publicOneTimePreKeys.map { X25519PublicKeyParameters(Base64.getDecoder().decode(it)) },
            preKeySignature = Base64.getDecoder().decode(preKeySignature)
        )
    }
}