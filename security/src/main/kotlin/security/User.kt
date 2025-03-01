package security

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.crypto.DiffieHellman
import security.crypto.aesGcmDecrypt
import security.crypto.aesGcmEncrypt
import security.crypto.generateX25519KeyPair
import security.messages.DecryptedMessage
import security.messages.EncryptedMessage
import security.messages.X3DHPreKeys

class User(val podId: String) {
    var initialDHPublicKey: ByteArray? = null
    var targetPublicKey: ByteArray? = null
    var preKeys: X3DHPreKeys? = null

    var sharedKey: ByteArray? = null // chain key
    var sendingKey: ByteArray? = null // sending chain key
    var receivingKey: ByteArray? = null // receiving chain key

    var prevPublicKey: ByteArray? = null
    var DHKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters>? = null

    // Out-of-order message handling
    var skippedKeys = mutableMapOf<Int, ByteArray>()
    var sendingChainLength: Int = 0
    var receivingChainLength: Int = 0
    var PN: Int = 0
    var sentMessageId: Int = -1
    var receivedMessageId: Int = -1

    fun sendInitialMessage(input: ByteArray): EncryptedMessage {
        DHKeyPair = generateX25519KeyPair()
        val initialDHoutput = DiffieHellman(DHKeyPair!!.second, X25519PublicKeyParameters(initialDHPublicKey))
        sendingKey = KeyRatchet.SymmetricKeyRatchetRoot(this, initialDHoutput)
        return sendMessage(input)
    }

    fun sendMessage(input: ByteArray): EncryptedMessage {
        val messageId = sentMessageId
        sentMessageId++
        /*
            TODO: Send message to message system
         */
        val sequenceNumber = sendingChainLength

        // generates the new sendingKey
        val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, true)

        // associatedData = Ephemeral publicKey + public id key Alice + public id Key bob
        val associatedData = DHKeyPair!!.first.encoded + preKeys!!.publicIdentityPreKey.encoded + targetPublicKey!!

        // encrypt message
        val ciphertext = aesGcmEncrypt(input, messageKey, associatedData)
        return EncryptedMessage(messageId + 1, DHKeyPair!!.first.encoded, ciphertext!!, sequenceNumber, PN)
    }

    fun receiveMessage(message: EncryptedMessage, publicKey: ByteArray): DecryptedMessage {

        // Check if messageKey was skipped preciously
        if (message.messageId  <= receivedMessageId) {
            // get earlier determined messageKey and remove it from the map
            val messageKey = skippedKeys.get(message.messageId)
            skippedKeys.remove(message.messageId)

            val associatedData = publicKey + targetPublicKey!! + preKeys!!.publicIdentityPreKey.encoded

            // decrypt message
            val plaintext = aesGcmDecrypt(message.cipherText, messageKey!!, associatedData)
            return DecryptedMessage(message.messageId, publicKey, String(plaintext!!, Charsets.UTF_8))
        }

        /*
            TODO: Fetch message from message system
         */
        if (!publicKey.contentEquals(prevPublicKey)) {
            // handle skipped messages in the previous chain
            val skippedMessages = (message.PN - receivingChainLength).takeIf { message.PN > receivingChainLength } ?: 0
            if (message.PN > receivingChainLength) {
                handleSkippedMessages(skippedMessages)
            }

            PN = sendingChainLength + skippedMessages

            // Does a DH ratchet when we receive a new public key
            val dhOutputs = KeyRatchet.DiffieHellmanRatchet(this, publicKey)
            receivingKey = KeyRatchet.SymmetricKeyRatchetRoot(this, dhOutputs!!.first)
            sendingKey = KeyRatchet.SymmetricKeyRatchetRoot(this, dhOutputs.second)


            // handle skipped messages in the current chain
            if (message.N > 0) {
                handleSkippedMessages(message.N)
                receivingChainLength = message.N
            }
            sendingChainLength = 0
        }
        else {
            // handle skipped messages
            if (message.N > receivingChainLength) {
                handleSkippedMessages(message.N - receivingChainLength)
            }
        }
        receivedMessageId++
        // generates the new receivingKey
        val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, false)

        // associatedData = Ephemeral publicKey + public id key Alice + public id Key bob
        val associatedData = publicKey + targetPublicKey!! + preKeys!!.publicIdentityPreKey.encoded

        // decrypt message
        val plaintext = aesGcmDecrypt(message.cipherText, messageKey, associatedData)
        return DecryptedMessage(message.messageId, publicKey, String(plaintext!!, Charsets.UTF_8))
    }

    private fun handleSkippedMessages(skippedMessages: Int) {
        for (i in 1..skippedMessages) {
            val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, false)
            skippedKeys.put(receivedMessageId + 1, messageKey)
            receivedMessageId++
        }
    }
}











