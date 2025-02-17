package kvasir.definitions.security

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters

fun HKDF(salt: ByteArray, inputKeyingMaterial: ByteArray, info:ByteArray, outputLength: Int): ByteArray {
    val hkdf = HKDFBytesGenerator(SHA256Digest())

    val hkdfParams = HKDFParameters(inputKeyingMaterial, salt, info)
    hkdf.init(hkdfParams)

    val derivedKey = ByteArray(outputLength)
    hkdf.generateBytes(derivedKey, 0, outputLength)

    return derivedKey
}