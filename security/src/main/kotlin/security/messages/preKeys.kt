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
    val publicOneTimePrekeys: X25519PublicKeyParameters,
    val preKeySignature: ByteArray,
    val privateIdentityPreKey: X25519PrivateKeyParameters,
    val privateSignedPrekey: X25519PrivateKeyParameters,
    val privateOneTimePrekeys: X25519PrivateKeyParameters
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
    val publicOneTimePreKeys: X25519PublicKeyParameters,
    val preKeySignature: ByteArray
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class X3DHPublicKeysAsString(
    @JsonProperty("kss_publicIdentityPreKeyEd25519") val publicIdentityPreKeyEd25519: String,
    @JsonProperty("kss_publicIdentityPreKeyX25519") val publicIdentityPreKeyX25519: String,
    @JsonProperty("kss_publicSignedPreKey") val publicSignedPreKey: String,
    @JsonProperty("kss_publicOneTimePreKeys") val publicOneTimePreKeys: String,
    @JsonProperty("kss_preKeySignature") val preKeySignature: String
) {
    fun convertFromString(): X3DHPublicPreKeys {
        return X3DHPublicPreKeys(
            publicIdentityPreKeyEd25519 = Ed25519PublicKeyParameters(Base64.getDecoder().decode(publicIdentityPreKeyEd25519)),
            publicIdentityPreKeyX25519 = X25519PublicKeyParameters(Base64.getDecoder().decode(publicIdentityPreKeyX25519)),
            publicSignedPreKey = X25519PublicKeyParameters(Base64.getDecoder().decode(publicSignedPreKey)),
            publicOneTimePreKeys = X25519PublicKeyParameters(Base64.getDecoder().decode(publicOneTimePreKeys)),
            preKeySignature = Base64.getDecoder().decode(preKeySignature)
        )
    }
}