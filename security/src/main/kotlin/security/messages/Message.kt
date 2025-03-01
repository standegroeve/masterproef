package security.messages

data class EncryptedMessage(
    val messageId: Int,
    val publicKey: ByteArray,
    val cipherText: ByteArray,
    val N: Int,
    val PN: Int
)

data class DecryptedMessage(
    val messageId: Int,
    val publicKey: ByteArray,
    val plainText: String
)