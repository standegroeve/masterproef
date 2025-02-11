package kvasir.security;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.rfc7748.X25519
import java.math.BigInteger
import java.security.*
import java.security.spec.EdECPrivateKeySpec
import java.security.spec.EdECPublicKeySpec
import java.security.spec.NamedParameterSpec
import java.security.spec.X509EncodedKeySpec
import kotlin.experimental.and
import kotlin.experimental.or


/*
*
*
*               CONSTANTS
*
*
* */


public val B = convert_mont(BigInteger("9"));
public val q = BigInteger("27742317777372353535851937790883648493").add(BigInteger.ONE.shiftLeft(252))
public val b = 256
public val p = BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
public val d: BigInteger = BigInteger("-121665").divide(BigInteger("121666"))

/*
*
*
* */



data class EdwardsPoint(val y: BigInteger, val s: BigInteger) {
    fun add(other: EdwardsPoint): EdwardsPoint {
        return EdwardsPoint(y+other.y, s+other.s);
    }

    fun double(): EdwardsPoint {
        return EdwardsPoint(y.multiply(BigInteger.TWO),s.multiply(BigInteger.TWO))
    }

    fun scalarMultiplication(k : ByteArray): EdwardsPoint {
        var R0: EdwardsPoint = EdwardsPoint(BigInteger.ZERO,BigInteger.ZERO);
        var R1: EdwardsPoint = this;

        for (byte: Byte in k) {
            for (bitIndex in 7 downTo 0) {
                val bit = (byte.toInt() shr bitIndex) and 1

                // Double both points
                R0 = R0.double()
                R1 = R1.double()

                if (bit == 1) {
                    R0 = R0.add(R1)
                } else {
                    R1 = R0.add(R1)
                }
            }
        }
        return R0;
    }

    fun encode(): ByteArray {
        val byteArray = y.toByteArray().copyOfRange(0,32)

        // Set the last bit equal to s (the sign bit)
        byteArray[31] = byteArray[31].and(0x7F.toByte())
        // Set the sign bit to `s` (0 or 1)
        byteArray[31] = byteArray[31].or((((s.toByte() and 0x01).toInt() shl 7).toByte()))

        return byteArray
    }

    fun onCurve(): Boolean {
        val leftSide = y.multiply(y) + s.multiply(s)
        val rightSide = BigInteger.ONE + d.multiply(y).multiply(y).multiply(s).multiply(s)
        return leftSide == rightSide
    }
}

fun convert_mont(u: BigInteger): EdwardsPoint {
    // mask u to the order of p which is 255 bits
    val u_masked: BigInteger = u.and(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE));

    val P: EdwardsPoint = EdwardsPoint(u_to_y(u_masked), BigInteger.ZERO);

    return P;
}

fun u_to_y(u: BigInteger): BigInteger {

    // Calculate mod inverse for division
    val denominatorInv = (u.add(BigInteger.ONE)).modInverse(p)

    // divide by multiplying with the inverse
    return u.minus(BigInteger.ONE).multiply(denominatorInv).mod(p);
}

fun calculate_key_pair(k : X25519PrivateKeyParameters) : Pair<Ed25519PublicKeyParameters, Ed25519PrivateKeyParameters> {
    val E: EdwardsPoint = B.scalarMultiplication(k.encoded)

    val A = EdwardsPoint(E.y, E.s)
    var a: BigInteger

    val scalar = BigInteger(1,k.encoded)
    if (E.s.equals(1)) {
        a =  scalar.negate().mod(q)
    }
    else {
        a = scalar.mod(q)
    }

    val ed25519PublicKeyParams = Ed25519PublicKeyParameters(A.encode(), 0)
    val ed25519PrivateKeyParams = Ed25519PrivateKeyParameters(a.toByteArray(),0)

    return Pair(ed25519PublicKeyParams,ed25519PrivateKeyParams);
}


//// Converts montgomery X25519PrivateKey to Edwards Ed25519KeyPair
//fun convert_mont(u: X25519PrivateKeyParameters): Pair<Ed25519PrivateKeyParameters, Ed25519PublicKeyParameters> {
//
//    // Convert x25519 private key to ed25519 keys
//    val ed25519PrivateKeyParams: Ed25519PrivateKeyParameters = Ed25519PrivateKeyParameters(u.encoded, 0)
//    val ed25519PublicKeyParams: Ed25519PublicKeyParameters = ed25519PrivateKeyParams.generatePublicKey()
//
//    // Create factory to convert ed25519 keys to Java KeyPair
//    val keyFactory: KeyFactory = KeyFactory.getInstance("Ed25519")
//
//    // Get private key
//    val privateKeySpec = EdECPrivateKeySpec(NamedParameterSpec.ED25519, ed25519PrivateKeyParams.encoded)
//    val privateKey: PrivateKey = keyFactory.generatePrivate(privateKeySpec)
//
//    // Get public key
//    val publicKeySpec = X509EncodedKeySpec(ed25519PublicKeyParams.encoded)
//    val publicKey: PublicKey = keyFactory.generatePublic(publicKeySpec)
//
//    return Pair(ed25519PrivateKeyParams, ed25519PublicKeyParams);
//}




