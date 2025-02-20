package security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

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