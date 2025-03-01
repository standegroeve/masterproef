package security.crypto;

import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.messages.X3DHPreKeys
import java.math.BigInteger
import java.security.SecureRandom


/*
       Calculates a Ed25519 Keypair using a Montogmery private key
 */
fun calculate_key_pair(k: X25519PrivateKeyParameters) : Pair<Ed25519PublicKeyParameters, Ed25519PrivateKeyParameters> {
    val sk = k.encoded
    require(sk.size == 32) { "X25519 private key must be 32 bytes" }

    val edPrivateKey = Ed25519PrivateKeyParameters(sk, 0)
    val edPublicKey = edPrivateKey.generatePublicKey()

    return Pair(edPublicKey, edPrivateKey)
}

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
        identityKeyPair.first,
        signedPreKeyPair.first,
        oneTimePreKeyPairs.map { it.first },
        signature,
        identityKeyPair.second,
        signedPreKeyPair.second,
        oneTimePreKeyPairs.map { it.second },
    )
}





