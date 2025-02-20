package security

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.messages.X3DHPreKeys
import java.util.*

class User(val podId: String) {
    var preKeys: X3DHPreKeys? = null
    var sharedKey: ByteArray? = null // chain key

    var prevPublicKey: ByteArray? = null
    var DHKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters>? = null


    fun DiffieHellmanRatchet(publicKey: ByteArray): Pair<ByteArray?, ByteArray?>? {
        if (publicKey.contentEquals(prevPublicKey)) {
            return null
        }

        var result: Pair<ByteArray?, ByteArray?>?
        if (DHKeyPair == null) {
            // Happens only at the start when no public key has been exchanged
            DHKeyPair = generateX25519KeyPair()
            result = Pair(null, DiffieHellman(DHKeyPair!!.second, X25519PublicKeyParameters(publicKey,0)))
        } else {
            val DH1 = DiffieHellman(DHKeyPair!!.second, X25519PublicKeyParameters(publicKey,0))
            DHKeyPair = generateX25519KeyPair()
            val DH2 =  DiffieHellman(DHKeyPair!!.second, X25519PublicKeyParameters(publicKey,0))
            result = Pair(DH1, DH2)
        }
        prevPublicKey = publicKey
        // return previous and current DH output
        return result
    }

    fun SymmetricKeyRatchet(DHOutput: ByteArray): Pair<ByteArray, ByteArray> {
        val chainKey: ByteArray = sharedKey!!
        val prk: ByteArray = HKDF(salt = chainKey, inputKeyingMaterial = DHOutput, info = "prk".toByteArray(), outputLength = 32)
        val newChainKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "chain".toByteArray(), outputLength = 32)
        val messageKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "message".toByteArray(), outputLength = 32)
        sharedKey = newChainKey
        return Pair(newChainKey, messageKey)
    }
}











