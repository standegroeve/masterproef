package security

import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.crypto.CryptoUtils.DiffieHellman
import security.crypto.CryptoUtils.HKDF
import security.crypto.KeyUtils.generateX25519KeyPair

object KeyRatchet  {
    fun DiffieHellmanRatchet(user: User, publicKey: ByteArray, targetPodId: String): Pair<ByteArray, ByteArray>? {
        if (publicKey.contentEquals(user.prevPublicKeyMap.get(targetPodId))) {
            return null
        }

        val DH1 = DiffieHellman(user.DHKeyPairMap.get(targetPodId)!!.second, X25519PublicKeyParameters(publicKey,0))
        user.DHKeyPairMap.put(targetPodId, generateX25519KeyPair())
        val DH2 =  DiffieHellman(user.DHKeyPairMap.get(targetPodId)!!.second, X25519PublicKeyParameters(publicKey,0))
        user.prevPublicKeyMap.put(targetPodId, publicKey)
        // return previous and current DH output
        return Pair(DH1, DH2)
    }

    fun SymmetricKeyRatchetRoot(user: User, inputKeyingMaterial: ByteArray, targetPodId: String): ByteArray {
        user.sendingChainLengthMap.put(targetPodId, 0)
        user.receivingChainLengthMap.put(targetPodId, 0)

        val prk: ByteArray = HKDF(salt = user.sharedKeysMap.get(targetPodId)!!, inputKeyingMaterial = inputKeyingMaterial, info = "prk".toByteArray(), outputLength = 32)
        val newChainKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "chain".toByteArray(), outputLength = 32)
        val messageKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "message".toByteArray(), outputLength = 32)
        user.sharedKeysMap.put(targetPodId, newChainKey)
        return messageKey
    }

    fun SymmetricKeyRatchetNonRoot(user: User, sendingRatchet: Boolean, targetPodId: String): ByteArray {
        val chainKey = if (sendingRatchet) user.sendingKeyMap.get(targetPodId) else user.receivingKeyMap.get(targetPodId)

        val prk: ByteArray = HKDF(salt = chainKey!!, inputKeyingMaterial = ByteArray(0), info = "prk".toByteArray(), outputLength = 32)
        val newChainKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "chain".toByteArray(), outputLength = 32)
        val messageKey: ByteArray = HKDF(salt = prk, inputKeyingMaterial = ByteArray(0), info = "message".toByteArray(), outputLength = 32)

        if (sendingRatchet) {
            user.sendingChainLengthMap.put(targetPodId, (user.sendingChainLengthMap.get(targetPodId)?.plus(1)) ?: 1)
            user.sendingKeyMap.put(targetPodId, newChainKey)
        }
        else {
            user.receivingChainLengthMap.put(targetPodId, (user.receivingChainLengthMap.get(targetPodId)?.plus(1)) ?: 1)
            user.receivingKeyMap.put(targetPodId, newChainKey)
        }
        return messageKey
    }
}