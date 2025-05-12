package security.crypto

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object CryptoUtils{

    fun aesGcmEncrypt(plaintext: ByteArray, aesKeyBytes: ByteArray, associatedData: ByteArray): ByteArray? {
        val nonce = ByteArray(12)
        SecureRandom().nextBytes(nonce)

        val aesKey = SecretKeySpec(aesKeyBytes, "AES")

        val gcmSpec = GCMParameterSpec(128, nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec)

        cipher.updateAAD(associatedData)

        val ciphertext = cipher.doFinal(plaintext)

        return nonce + ciphertext
    }

    fun aesGcmDecrypt(ciphertextWithTag: ByteArray, aesKeyBytes: ByteArray, associatedData: ByteArray): ByteArray? {
        // Split nonce and ciphertext
        val nonce = ciphertextWithTag.copyOfRange(0, 12)
        val ciphertext = ciphertextWithTag.copyOfRange(12, ciphertextWithTag.size)

        val aesKey = SecretKeySpec(aesKeyBytes, "AES")

        val gcmSpec = GCMParameterSpec(128, nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec)

        cipher.updateAAD(associatedData)

        return cipher.doFinal(ciphertext)
    }

    fun HKDF(salt: ByteArray, inputKeyingMaterial: ByteArray, info:ByteArray, outputLength: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())

        val hkdfParams = HKDFParameters(inputKeyingMaterial, salt, info)
        hkdf.init(hkdfParams)

        val derivedKey = ByteArray(outputLength)
        hkdf.generateBytes(derivedKey, 0, outputLength)

        return derivedKey
    }

    fun DiffieHellman(privateKey: X25519PrivateKeyParameters, publicKey: X25519PublicKeyParameters): ByteArray {
        val keyAgreement = X25519Agreement()
        keyAgreement.init(privateKey)
        val sharedSecret = ByteArray(keyAgreement.agreementSize)
        keyAgreement.calculateAgreement(publicKey, sharedSecret, 0)
        return sharedSecret
    }
}