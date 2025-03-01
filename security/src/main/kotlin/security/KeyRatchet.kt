package security

import org.bouncycastle.crypto.params.X25519PublicKeyParameters

object KeyRatchet  {
    fun DiffieHellmanRatchet(user: User, publicKey: ByteArray): Pair<ByteArray, ByteArray>? {
        if (publicKey.contentEquals(user.prevPublicKey)) {
            return null
        }

        val DH1 = DiffieHellman(user.DHKeyPair!!.second, X25519PublicKeyParameters(publicKey,0))
        user.DHKeyPair = generateX25519KeyPair()
        val DH2 =  DiffieHellman(user.DHKeyPair!!.second, X25519PublicKeyParameters(publicKey,0))
        user.prevPublicKey = publicKey
        // return previous and current DH output
        return Pair(DH1, DH2)
    }

    fun SymmetricKeyRatchetRoot(user: User, inputKeyingMaterial: ByteArray): ByteArray {
        user.sendingChainLength = 0
        user.receivingChainLength = 0

        val prk: ByteArray = HKDF(salt = user.sharedKey!!, inputKeyingMaterial = inputKeyingMaterial, info = "prk".toByteArray(), outputLength = 32)
        val newChainKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "chain".toByteArray(), outputLength = 32)
        val messageKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "message".toByteArray(), outputLength = 32)
        user.sharedKey = newChainKey
        return messageKey
    }

    fun SymmetricKeyRatchetNonRoot(user: User, sendingRatchet: Boolean): ByteArray {
        val chainKey = if (sendingRatchet) user.sendingKey else user.receivingKey

        val prk: ByteArray = HKDF(salt = chainKey!!, inputKeyingMaterial = ByteArray(0), info = "prk".toByteArray(), outputLength = 32)
        val newChainKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "chain".toByteArray(), outputLength = 32)
        val messageKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "message".toByteArray(), outputLength = 32)

        if (sendingRatchet) {
            user.sendingChainLength++
            user.sendingKey = newChainKey
        }
        else {
            user.receivingChainLength++
            user.receivingKey = newChainKey
        }
        return messageKey
    }
}