package kvasir.security

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.math.BigInteger
import java.security.MessageDigest

private val sha512 = MessageDigest.getInstance("SHA-512")


fun hash_i(X: ByteArray, i: BigInteger): ByteArray {
    val sha512 = MessageDigest.getInstance("SHA-512")

    val bytesToHash = BigInteger.ONE.shiftLeft(256).minus(BigInteger.ONE).minus(i).toByteArray() + X

    return sha512.digest(bytesToHash)
}


fun xeddsa_sign(k: X25519PrivateKeyParameters, message: ByteArray, Z: ByteArray): ByteArray {
    // Calculate Public, Private Ed25519 keypair
    val edwardsKeyPair = calculate_key_pair(k)
    val A: Ed25519PublicKeyParameters = edwardsKeyPair.first;
    val a: Ed25519PrivateKeyParameters = edwardsKeyPair.second

    val r: ByteArray = BigInteger(hash_i(a.encoded + message + Z, BigInteger.ONE)).mod(q).toByteArray()

    val R: ByteArray = B.scalarMultiplication(r).encode()

    val h: ByteArray = BigInteger(sha512.digest(R + A.encoded + message)).mod(q).toByteArray()

    val s: ByteArray = BigInteger(r).add(BigInteger(h).multiply(BigInteger(a.encoded)) % q).toByteArray()

    return R + s;
}

fun xeddsa_verify(u: X25519PublicKeyParameters, message: ByteArray, signature: ByteArray): Boolean {
    val R = signature.copyOfRange(0, 32)  // First 32 bytes are R
    val s = signature.copyOfRange(32, 64)  // Next 32 bytes are s

    if (BigInteger(u.encoded) >= p || BigInteger(R) >= BigInteger.ONE.shiftLeft(255) || BigInteger(s) >= BigInteger.ONE.shiftLeft(253)) {
        return false
    }

    val A: EdwardsPoint = convert_mont(BigInteger(u.encoded))

    if (!A.onCurve()) {
        return false
    }

    val h: ByteArray = BigInteger(sha512.digest(R + A.encode() + message)).mod(q).toByteArray()
    val Rcheck = BigInteger(s).multiply(BigInteger(B.encode())).minus(BigInteger(h).multiply(BigInteger(A.encode())))

    if (R.equals(Rcheck)) {
        return true
    }
    return false
}



