package kvasir.definitions.security

import kvasir.definitions.kg.X3DHPreKeys
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import java.util.*


fun generateX25519KeyPair(): Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters> {
    val secureRandom = SecureRandom()

    // Key generation parameters
    val keyGenParams = KeyGenerationParameters(secureRandom, 256)
    val keyPairGenerator = org.bouncycastle.crypto.generators.X25519KeyPairGenerator()
    keyPairGenerator.init(keyGenParams)

    val keyPair = keyPairGenerator.generateKeyPair()
    val privateKey = keyPair.private as X25519PrivateKeyParameters
    val publicKey = keyPair.public as X25519PublicKeyParameters

    return Pair(publicKey, privateKey)
}

fun generatePrekeys(): X3DHPreKeys {
    val identityKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters> = generateX25519KeyPair()
    val signedPreKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters> = generateX25519KeyPair()
    val signature: ByteArray = xeddsa_sign(identityKeyPair.second, signedPreKeyPair.first.encoded)
    // create a list with one-time keyPairs
    val oneTimePreKeyPairs: List<Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters>> = (1..5).map {
        generateX25519KeyPair()
    }

    return X3DHPreKeys(
        Base64.getEncoder().encodeToString(identityKeyPair.first.encoded),
        Base64.getEncoder().encodeToString(signedPreKeyPair.second.encoded),
        oneTimePreKeyPairs.map { Base64.getEncoder().encodeToString(it.first.encoded) },
        Base64.getEncoder().encodeToString(signature),
        Base64.getEncoder().encodeToString(identityKeyPair.second.encoded),
        Base64.getEncoder().encodeToString(signedPreKeyPair.second.encoded),
        oneTimePreKeyPairs.map { Base64.getEncoder().encodeToString(it.second.encoded) }
    )
}

fun sendInitialMessage() {

}

fun processInitialMessage() {

}

