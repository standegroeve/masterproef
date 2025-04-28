package security.crypto

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import security.crypto.KeyUtils.calculate_key_pair

object XEdDSA {
    fun xeddsa_sign(x25519PrivateKey: X25519PrivateKeyParameters, message: ByteArray): ByteArray {
        val (_, edPrivateKey) = calculate_key_pair(x25519PrivateKey)
        val signer = Ed25519Signer()
        signer.init(true, edPrivateKey)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    fun xeddsa_verify(ed25519PublicKey: Ed25519PublicKeyParameters, message: ByteArray, signature: ByteArray): Boolean {
        val verifier = Ed25519Signer()
        verifier.init(false, ed25519PublicKey)
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }
}
