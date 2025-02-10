package kvasir.security;

import java.math.BigInteger
import java.security.PrivateKey
import java.security.PublicKey
import kotlin.math.abs

data class KeyPair(val privateKey: PrivateKey, val publicKey: PublicKey)

data class MontgomeryPoint(val x: BigInteger, val y: BigInteger)

data class EdwardsPoint(val x: BigInteger, val y: BigInteger)

fun calculate_key_pair(k : Int) : Int {
    /*

        TO DO

    */

    return 1;
}

fun convert_to_mont(u: BigInteger): EdwardsPoint {
    // mask u to the order of p which is 255 bits
    val u_masked: BigInteger = u.and(BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE));

    val P: EdwardsPoint = EdwardsPoint(u_to_y(u), BigInteger.ZERO);

    return P;
}

fun u_to_y(u: BigInteger): BigInteger {

    val p = BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed")
    // Calculate mod inverse for division
    val denominatorInv = (u.add(BigInteger.ONE)).modInverse(p)

    // divide by multiplying with the inverse
    return u.minus(BigInteger.ONE).multiply(denominatorInv).mod(p);
}

