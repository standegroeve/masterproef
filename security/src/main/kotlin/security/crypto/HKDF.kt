package security.crypto

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.agreement.*

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