package security

import org.apache.kafka.shaded.com.google.protobuf.Timestamp
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.crypto.CryptoUtils.DiffieHellman
import security.crypto.CryptoUtils.aesGcmDecrypt
import security.crypto.CryptoUtils.aesGcmEncrypt
import security.crypto.KeyUtils.generateX25519KeyPair
import security.messages.DecryptedMessage
import security.messages.EncryptedMessage
import security.messages.X3DHPreKeys
import java.nio.ByteBuffer

class User(val podId: String) {
    var initialDHPublicKey: ByteArray? = null
    var targetPublicKey: ByteArray? = null
    var preKeys: X3DHPreKeys? = null

    var sharedKey: ByteArray? = null // chain key
    var sendingKey: ByteArray? = null // sending chain key
    var receivingKey: ByteArray? = null // receiving chain key

    var prevPublicKey: ByteArray? = null
    var DHKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters>? = null

    var hashedPodId: String? = null
    var targetHashedPodId: String? = null

    // Out-of-order message handling
    var skippedKeys = mutableMapOf<Int, ByteArray>()
    var sendingChainLength: Int = 0
    var receivingChainLength: Int = 0
    var PN: Int = 0
    var sentMessageId: Int = -1
    var receivedMessageId: Int = -1

    var latestReceivedMessageId = -1

    fun sendInitialMessage(targetPod: String, input: ByteArray, timestampBytes: ByteArray, authenticationCode: String) {
        DHKeyPair = generateX25519KeyPair()
        val initialDHoutput = DiffieHellman(DHKeyPair!!.second, X25519PublicKeyParameters(initialDHPublicKey))
        sendingKey = KeyRatchet.SymmetricKeyRatchetRoot(this, initialDHoutput)
        sendMessage(targetPod, input, timestampBytes, authenticationCode)
    }

    fun sendMessage(targetPod: String, input: ByteArray, timestampBytes: ByteArray, authenticationCode: String) {
        val messageId = sentMessageId
        sentMessageId++

        val sequenceNumber = sendingChainLength

        // generates the new sendingKey
        val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, true)

        // associatedData = Ephemeral publicKey + public id key Alice + public id Key bob
        val associatedData = DHKeyPair!!.first.encoded + preKeys!!.publicIdentityPreKey.encoded + targetPublicKey!!

        // encrypt message
        val ciphertext = aesGcmEncrypt(timestampBytes + input, messageKey, associatedData)
        val encrpytedMessage = EncryptedMessage(messageId + 1, DHKeyPair!!.first.encoded, ciphertext!!, sequenceNumber, PN)

        // sends the message to the pod
        messageController.sendMessage(targetHashedPodId!!, targetPod, encrpytedMessage, authenticationCode)
    }

    fun receiveMessage(targetPod: String, authenticationCode: String): List<DecryptedMessage> {
        // Retreive messages which we havent seen already or whose key isnt in skippedKeys
        val encryptedMessages = messageController.retrieveMessages(hashedPodId!!, targetPod, latestReceivedMessageId, skippedKeys, authenticationCode)

        var messagesList = mutableListOf<DecryptedMessage>()
        for (i in 0..encryptedMessages.size-1) {
            val message = encryptedMessages[i]

            if (message.messageId > latestReceivedMessageId)
                latestReceivedMessageId = message.messageId

            // Check if messageKey was skipped previously
            if (message.messageId  <= receivedMessageId) {
                // get earlier determined messageKey and remove it from the map
                val messageKey = skippedKeys.get(message.messageId)
                skippedKeys.remove(message.messageId)

                val associatedData = message.publicKey + targetPublicKey!! + preKeys!!.publicIdentityPreKey.encoded

                // decrypt message
                val decryptedData = aesGcmDecrypt(message.cipherText, messageKey!!, associatedData)
                messagesList.add(DecryptedMessage(message.messageId, message.publicKey, String(decryptedData!!.copyOfRange(8, decryptedData.size), Charsets.UTF_8), ByteBuffer.wrap(decryptedData.copyOfRange(0, 8)).long))
                continue
            }


            if (!message.publicKey.contentEquals(prevPublicKey)) {
                // handle skipped messages in the previous chain
                val skippedMessages = (message.PN - receivingChainLength).takeIf { message.PN > receivingChainLength } ?: 0
                if (message.PN > receivingChainLength) {
                    handleSkippedMessages(skippedMessages)
                }

                PN = sendingChainLength + skippedMessages

                // Does a DH ratchet when we receive a new public key
                val dhOutputs = KeyRatchet.DiffieHellmanRatchet(this, message.publicKey)
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
            val associatedData = message.publicKey + targetPublicKey!! + preKeys!!.publicIdentityPreKey.encoded

            // decrypt message
            val decryptedData = aesGcmDecrypt(message.cipherText, messageKey, associatedData)

            messagesList.add(DecryptedMessage(message.messageId, message.publicKey, String(decryptedData!!.copyOfRange(8, decryptedData.size), Charsets.UTF_8), ByteBuffer.wrap(decryptedData.copyOfRange(0, 8)).long))
        }

        return messagesList
    }

    private fun handleSkippedMessages(skippedMessages: Int) {
        for (i in 1..skippedMessages) {
            val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, false)
            skippedKeys.put(receivedMessageId + 1, messageKey)
            receivedMessageId++
        }
    }
}











