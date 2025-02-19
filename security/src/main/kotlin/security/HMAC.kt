package security


//fun HMAC(key: X25519PrivateKeyParameters, text: ByteArray): ByteArray {
//    val sha256Digest = SHA256Digest()
//    val hmac = HMac(sha256Digest)
//    val keyParameter = KeyParameter(key.encoded)
//    hmac.init(keyParameter)
//    hmac.update(text, 0, text.size)
//    val result = ByteArray(hmac.macSize)
//    hmac.doFinal(result,0)
//    return result
//}
