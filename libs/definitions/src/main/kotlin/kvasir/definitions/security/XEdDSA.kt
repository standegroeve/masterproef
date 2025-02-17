package kvasir.definitions.security

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.math.BigInteger
import kotlin.experimental.and

/*

 */
fun xeddsa_sign(x25519PrivateKey: X25519PrivateKeyParameters, message: ByteArray): ByteArray {
    val (_, edPrivateKey) = calculate_key_pair(x25519PrivateKey)
    val signer = Ed25519Signer()
    signer.init(true, edPrivateKey)
    signer.update(message, 0, message.size)
    return signer.generateSignature()
}

fun xeddsa_verify(x25519PublicKey: X25519PublicKeyParameters, x25519PrivateKey: X25519PrivateKeyParameters, message: ByteArray, signature: ByteArray): Boolean {
    //val edPublicKey = Ed25519PublicKeyParameters(x25519PublicKey.encoded, 0)
    val pkey = x25519ToEd25519(x25519PublicKey.encoded)
    val (edPublicKey:Ed25519PublicKeyParameters, _) = calculate_key_pair(x25519PrivateKey)
    val pkey_encoded = edPublicKey.encoded
    val verifier = Ed25519Signer()
    verifier.init(false, edPublicKey)
    verifier.update(message, 0, message.size)
    return verifier.verifySignature(signature)
}



fun x25519ToEd25519(x25519PublicKey: ByteArray): ByteArray? {
    if (x25519PublicKey.size != 32) return null

    val u = x25519PublicKey.reversedArray()

    val recip = BigInteger.ONE.modInverse(Curve25519Constants.p)

    val y = MontgomeryPoint(BigInteger(u)).u_to_y().mod(Curve25519Constants.p).multiply(recip)

//    // Compute x = sqrt((y^2 - 1) / (d * y^2 + 1)) mod p
//    val y2 = y.multiply(y).mod(P)
//    val num = y2.subtract(one).mod(P)
//    val denom = D.multiply(y2).add(one).mod(P)
//    val denomInv = denom.modInverse(P)
//    val x2 = num.multiply(denomInv).mod(P)
//
//    // Compute square root of x2 mod p (assuming sign bit = 0)
//    val x = sqrtModP(x2)
//    if (x == null) return null // No valid square root found

    // Encode Ed25519 public key (y + sign bit)
    val ed25519PubKey = y.toByteArray().copyOf(32).reversedArray()
    ed25519PubKey[31] = ed25519PubKey[31] and 0x7F.toByte() // Set sign bit to 0

    return ed25519PubKey
}




