package kvasir.security

import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters



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
