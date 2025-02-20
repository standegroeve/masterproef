package security

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.messages.X3DHPreKeys
import java.util.*

class User(val podId: String) {
    var targetIdentity: X25519PublicKeyParameters? = null
    var preKeys: X3DHPreKeys? = null
    var sharedKey: ByteArray? = null

    var DHKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters>? = null


    fun DiffieHellmanRatchet(publicKey: ByteArray): ByteArray? {
        DHKeyPair = generateX25519KeyPair()

        return targetIdentity?.let { DiffieHellman(DHKeyPair!!.second, it) }
    }
}











