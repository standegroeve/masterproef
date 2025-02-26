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
    var sendingKey: ByteArray? = null // sending chain key
    var receivingKey: ByteArray? = null // receiving chain key

    var prevPublicKey: ByteArray? = null
    var DHKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters> = generateX25519KeyPair()


    fun DiffieHellmanRatchet(publicKey: ByteArray): Pair<ByteArray, ByteArray>? {
        if (publicKey.contentEquals(prevPublicKey)) {
            return null
        }

        val DH1 = DiffieHellman(DHKeyPair.second, X25519PublicKeyParameters(publicKey,0))
        DHKeyPair = generateX25519KeyPair()
        val DH2 =  DiffieHellman(DHKeyPair.second, X25519PublicKeyParameters(publicKey,0))
        prevPublicKey = publicKey
        // return previous and current DH output
        return Pair(DH1, DH2)
    }

    fun SymmetricKeyRatchetRoot(inputKeyingMaterial: ByteArray): ByteArray {
        val prk: ByteArray = HKDF(salt = sharedKey!!, inputKeyingMaterial = inputKeyingMaterial, info = "prk".toByteArray(), outputLength = 32)
        val newChainKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "chain".toByteArray(), outputLength = 32)
        val messageKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "message".toByteArray(), outputLength = 32)
        sharedKey = newChainKey
        return messageKey
    }

    fun SymmetricKeyRatchetNonRoot(sendingRatchet: Boolean): ByteArray {
        val chainKey = if (sendingRatchet) sendingKey else receivingKey

        val prk: ByteArray = HKDF(salt = chainKey!!, inputKeyingMaterial = ByteArray(0), info = "prk".toByteArray(), outputLength = 32)
        val newChainKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "chain".toByteArray(), outputLength = 32)
        val messageKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "message".toByteArray(), outputLength = 32)

        if (sendingRatchet)
            sendingKey = newChainKey
        else
            receivingKey = newChainKey
        return messageKey
    }
}











