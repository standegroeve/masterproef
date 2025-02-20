package security;

import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.messages.X3DHPreKeys
import java.math.BigInteger
import java.security.SecureRandom


/*
*
*
*               CONSTANTS
*
*
* */

class Curve25519Constants private constructor() {
    companion object {
        val p: BigInteger by lazy {
            BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
        }

        val d: BigInteger by lazy {
            BigInteger("-121665").multiply(BigInteger("121666").modInverse(p)).mod(p)
        }

        val q: BigInteger by lazy {
            BigInteger("27742317777372353535851937790883648493").add(BigInteger.ONE.shiftLeft(252))
        }

        val B: MontgomeryPoint by lazy {
            MontgomeryPoint(BigInteger("9"))
        }

        val b: Int = 256
    }
}

/*
*
*
* */

data class MontgomeryPoint(val u: BigInteger) {

    /*
        Converts Montgomery u-coordinate to Edwards y-coordinate
     */
    fun u_to_y(): BigInteger {
        // Calculate mod inverse for division
        val denominatorInv = u.add(BigInteger.ONE).modInverse(Curve25519Constants.q)

        // divide by multiplying with the inverse
        return u.minus(BigInteger.ONE).multiply(denominatorInv).mod(Curve25519Constants.q).modInverse(Curve25519Constants.q);
    }

    /*
        Converts Montgomery u-coordinate to EdwardsPoint
     */
    fun convert_mont(): EdwardsPoint {
        // mask u to the order of p which is 255 bits
        val u_masked: BigInteger = u.and(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE));
        val P: EdwardsPoint = EdwardsPoint(MontgomeryPoint(u_masked).u_to_y(), BigInteger.ZERO);
        return P;
    }
}




data class EdwardsPoint(val y: BigInteger, val s: BigInteger) {
    //val x: BigInteger = CalculateX()

    /*
        Calculates the x-coordinate corresponding to the y-coordinate
     */
//    fun CalculateX(): BigInteger {
//        val numerator: BigInteger = modularSquareRoot((Curve25519Constants.d.multiply(y).multiply(y).add(BigInteger.ONE)).multiply(y.multiply(y).minus(BigInteger.ONE)).mod(Curve25519Constants.p), Curve25519Constants.p)
//        val denominator: BigInteger = Curve25519Constants.d.multiply(y).multiply(y).add(BigInteger.ONE)
//
//        if (denominator.signum() == 0) {
//            throw IllegalArgumentException("Invalid y-coordinate: Division by zero encountered.");
//        }
//
//        var unsigned_x_squared = numerator.multiply(denominator.modInverse(Curve25519Constants.p)).mod(Curve25519Constants.p)
//
//        var signS = 1
//        if (s.signum().equals(-1)) {
//            signS = -1;
//        }
//        return BigInteger(signS.toString()).multiply(unsigned_x_squared)
//    }

    /*
        Determines the modularSquareRoot based on the Tonelli-Shanks algorithm
     */
//    fun modularSquareRoot(a: BigInteger, p: BigInteger): BigInteger {
//        if (a == BigInteger.ZERO) return BigInteger.ZERO
//        if (p.mod(BigInteger.valueOf(4)) == BigInteger.valueOf(3)) {
//            return a.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p)
//        }
//
//        // Step 1: Check if a is a quadratic residue mod p
//        if (a.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.TWO), p) != BigInteger.ONE) {
//            throw ArithmeticException("Error in modularSquareRoot: no quadratic residue")
//            // No solution exists
//        }
//
//        // Step 2: Factor p - 1 as q * 2^s
//        var q = p.subtract(BigInteger.ONE)
//        var s = 0
//        while (q.mod(BigInteger.TWO) == BigInteger.ZERO) {
//            q = q.divide(BigInteger.TWO)
//            s++
//        }
//
//        // Step 3: Find a non-quadratic residue z
//        var z = BigInteger.TWO
//        while (z.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.TWO), p) == BigInteger.ONE) {
//            z = z.add(BigInteger.ONE)
//        }
//
//        // Step 4: Initialize variables
//        var m = s
//        var c = z.modPow(q, p)
//        var t = a.modPow(q, p)
//        var r = a.modPow(q.add(BigInteger.ONE).divide(BigInteger.TWO), p)
//
//        // Step 5: Iterate until t == 1
//        while (t != BigInteger.ONE) {
//            var i = 0
//            var tPow = t
//            while (tPow != BigInteger.ONE && i < m) {
//                tPow = tPow.modPow(BigInteger.TWO, p)
//                i++
//            }
//
//            if (i == m) {
//                throw ArithmeticException("Error in modularSquareRoot")
//            }
//
//            val b = c.modPow(BigInteger.TWO.pow(m - i - 1), p)
//            r = r.multiply(b).mod(p)
//            t = t.multiply(b).multiply(b).mod(p)
//            c = b.multiply(b).mod(p)
//            m = i
//        }
//
//        return r
//    }

    /*
        Adds two EdwardsPoints together
     */
//    fun add(other: EdwardsPoint): EdwardsPoint {
//        val y3 = (y.multiply(other.y).minus(x.multiply(other.x)))
//            .divide(BigInteger.ONE.minus(Curve25519Constants.d.multiply(x).multiply(other.x).multiply(y).multiply(other.y))).mod(Curve25519Constants.p)
//
//        var s = BigInteger.ONE
//        if (y3.signum() == -1) {
//            s = BigInteger.ZERO
//        }
//
//        return EdwardsPoint(y3, s)
//    }
//
//    /*
//        Doubles two EdwardsPoints
//     */
//    fun double(): EdwardsPoint {
//        val y3 = (y.multiply(y).minus(x.multiply(x)))
//            .divide(BigInteger.ONE.minus(Curve25519Constants.d.multiply(x).multiply(x).multiply(y).multiply(y))).mod(Curve25519Constants.p)
//
//        // Adjust the sign bit for Y3
//        var s = BigInteger.ONE
//        if (y3.signum() == -1) {
//            s = BigInteger.ZERO
//        }
//
//        return EdwardsPoint(y3, s)
//    }

    /*
        Multiplies a scalar as a ByteArray by an EdwardsPoint
     */
//    fun scalarMultiply(k: ByteArray): EdwardsPoint {
//        var R0 = EdwardsPoint(BigInteger.ZERO, BigInteger.ONE)  // Identity point
//        var R1: EdwardsPoint = this
//
//        // Loop over each byte in the ByteArray
//        for (byte: Byte in k) {
//            // Process each bit of the byte
//            for (bitIndex: Int in 7 downTo 0) {
//                val bit: Int = (byte.toInt() shr bitIndex) and 1
//
//                // Double both points
//                R0 = R0.double()
//                R1 = R1.double()
//
//                // Perform the addition based on the bit value
//                if (bit == 1) {
//                    R0 = R0.add(R1)
//                } else {
//                    R1 = R0.add(R1)
//                }
//            }
//        }
//        return R0
//    }

    /*
        Encodes the EdwardsPoints as the y-coordinate for b-1 bits followed by the s-bit
     */
//    fun encode(): ByteArray {
//        if (y.toByteArray().size > 32) {
//            throw IllegalArgumentException("y cannot be longer than 32 bytes")
//        }
//
//        val yBytes = y.toByteArray()
//        val byteArray = ByteArray(32)
//
//        // Add padding if y is not 32 bytes
//        val start = 32 - yBytes.size
//        yBytes.copyInto(byteArray, destinationOffset = start, startIndex = 0, endIndex = yBytes.size)
//
//
//
//
//        byteArray[31] = byteArray[31].and(0x7F.toByte()) // Clear highest bit
//        byteArray[31] = byteArray[31].or(((s.toByte() and 0x01).toInt() shl 7).toByte()) // Set sign bit
//
//        // Ed25519 clamping
//        byteArray[0] = byteArray[0].and(248.toByte())
//        byteArray[31] = byteArray[31].and(127.toByte())
//        byteArray[31] = byteArray[31].or(64.toByte())
//
//        return byteArray
//    }
//
//    fun onCurve(): Boolean {
//        val leftSide = y.multiply(y) + s.multiply(s)
//        val rightSide = BigInteger.ONE + Curve25519Constants.d.multiply(y).multiply(y).multiply(s).multiply(s)
//        return leftSide == rightSide
//    }
}

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





