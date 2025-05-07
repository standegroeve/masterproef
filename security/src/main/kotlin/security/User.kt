package security

import org.apache.jena.rdf.model.Statement
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
import security.partialEncrypt.RDFEncryptionProcessor
import java.nio.ByteBuffer
import java.util.*

class User(val podId: String) {
    var initialDHPublicKeyMap: MutableMap<String, ByteArray> = mutableMapOf()
    var targetPublicKeyMap: MutableMap<String, ByteArray> = mutableMapOf()
    var preKeysMap: MutableMap<String, X3DHPreKeys> = mutableMapOf()

    val sharedKeysMap: MutableMap<String, ByteArray> = mutableMapOf() // chain key
    var sendingKeyMap: MutableMap<String, ByteArray> = mutableMapOf() // sending chain key
    var receivingKeyMap: MutableMap<String, ByteArray> = mutableMapOf() // receiving chain key

    var prevPublicKeyMap: MutableMap<String, ByteArray> = mutableMapOf()
    var DHKeyPairMap: MutableMap<String, Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters>> = mutableMapOf()

    var hashedPodId: MutableMap<String, String> = mutableMapOf()
    var targetHashedPodId: MutableMap<String, String> = mutableMapOf()

    // Out-of-order message handling
    var skippedKeysMap: MutableMap<String, MutableMap<Int, ByteArray>> = mutableMapOf()
    var sendingChainLengthMap: MutableMap<String, Int> = mutableMapOf()
    var receivingChainLengthMap: MutableMap<String, Int> = mutableMapOf()
    var PNMap: MutableMap<String, Int> = mutableMapOf()
    var sentMessageIdMap: MutableMap<String, Int> = mutableMapOf()
    var receivedMessageIdMap: MutableMap<String, Int> = mutableMapOf()

    var latestReceivedMessageIdMap: MutableMap<String, Int> = mutableMapOf()

    fun sendInitialMessage(podId: String, input: ByteArray, timestampBytes: ByteArray, targetId: String, authenticationCode: String, keepStructure: Boolean, valuesToEncrypt: List<String> = emptyList(), tripleGroupsToEncrypt: List<List<Statement>> = emptyList()): String {
        DHKeyPairMap.put(targetId, generateX25519KeyPair())
        val initialDHoutput = DiffieHellman(DHKeyPairMap.get(targetId)!!.second, X25519PublicKeyParameters(initialDHPublicKeyMap.get(targetId)))
        sendingKeyMap.put(targetId, KeyRatchet.SymmetricKeyRatchetRoot(this, initialDHoutput, targetId))
        return sendMessage(podId, input, timestampBytes, targetId, authenticationCode, keepStructure, valuesToEncrypt, tripleGroupsToEncrypt)
    }

    fun sendMessage(podId: String, input: ByteArray, timestampBytes: ByteArray, targetId: String, authenticationCode: String, keepStructure: Boolean, valuesToEncrypt: List<String> = emptyList(), tripleGroupsToEncrypt: List<List<Statement>> = emptyList()): String {
        val messageId = sentMessageIdMap.get(targetId) ?: -1
        sentMessageIdMap.put(targetId, sentMessageIdMap.get(targetId)?.plus(1) ?: 0)

        val sequenceNumber = sendingChainLengthMap.get(targetId) ?: 0

        // generates the new sendingKey
        val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, true, targetId)

        // associatedData = Ephemeral publicKey + public id key Alice + public id Key bob
        val associatedData = DHKeyPairMap.get(targetId)!!.first.encoded + preKeysMap.get(targetId)!!.publicIdentityPreKey.encoded + targetPublicKeyMap.get(targetId)!!

        // encrypt message
        var ciphertext: Any? = null
        if (keepStructure) {
            ciphertext = RDFEncryptionProcessor.encryptRDF(String(input, Charsets.UTF_8), timestampBytes, messageKey, associatedData, valuesToEncrypt, tripleGroupsToEncrypt).toByteArray()
        }
        else {
            ciphertext = aesGcmEncrypt(timestampBytes + input, messageKey, associatedData)
        }
        val encrpytedMessage = EncryptedMessage(messageId!! + 1, DHKeyPairMap.get(targetId)!!.first.encoded, ciphertext as ByteArray, sequenceNumber, PNMap.get(targetId) ?: 0)

        // sends the message to the pod
        messageController.sendMessage(targetHashedPodId.get(targetId)!!, podId, encrpytedMessage, authenticationCode)

        return String(ciphertext, Charsets.UTF_8)
    }

    fun receiveMessage(podId: String, targetId: String, authenticationCode: String, keepStructure: Boolean): List<DecryptedMessage> {

        if (!hashedPodId.containsKey(targetId)) {
            return emptyList()
        }

        val encryptedMessages = messageController.retrieveMessages(hashedPodId.get(targetId)!!, podId, (latestReceivedMessageIdMap.get(targetId) ?: -1), skippedKeysMap.get(targetId) ?: mutableMapOf<Int, ByteArray>(), authenticationCode)


        var messagesList = mutableListOf<DecryptedMessage>()
        for (i in 0..encryptedMessages.size-1) {
            val message = encryptedMessages[i]

            if (message.messageId > (latestReceivedMessageIdMap.get(targetId) ?: -1))
                latestReceivedMessageIdMap.put(targetId, message.messageId)

            // Check if messageKey was skipped previously
            if (message.messageId  <= (receivedMessageIdMap.get(targetId) ?: -1)) {
                // get earlier determined messageKey and remove it from the map
                val messageKey = skippedKeysMap.get(targetId)!!.get(message.messageId)
                skippedKeysMap.get(targetId)!!.remove(message.messageId)

                val associatedData = message.publicKey + targetPublicKeyMap.get(targetId)!! + preKeysMap.get(targetId)!!.publicIdentityPreKey.encoded

                // decrypt message
                var decryptedString: String?
                var timestampBytes: Long?

                if (keepStructure) {
                    val result = RDFEncryptionProcessor.decryptRDF(String(message.cipherText, Charsets.UTF_8), messageKey!!, associatedData)
                    decryptedString = result.first
                    timestampBytes = result.second
                } else {
                    val decryptedData = aesGcmDecrypt(message.cipherText, messageKey!!, associatedData)
                    decryptedString = String(decryptedData!!.copyOfRange(8, decryptedData.size))
                    timestampBytes = ByteBuffer.wrap(decryptedData.copyOfRange(0, 8)).long
                }
                messagesList.add(DecryptedMessage(message.messageId, message.publicKey, decryptedString, timestampBytes))
                continue
            }


            if (!message.publicKey.contentEquals(prevPublicKeyMap.get(targetId))) {
                // handle skipped messages in the previous chain
                val skippedMessages = (message.PN - (receivingChainLengthMap.get(targetId)
                    ?: 0)).takeIf { message.PN > (receivingChainLengthMap.get(targetId) ?: -1) } ?: 0
                if (message.PN > receivingChainLengthMap.get(targetId) ?: 0) {
                    handleSkippedMessages(skippedMessages, targetId)
                }

                PNMap.put(targetId, (sendingChainLengthMap.get(targetId) ?: 0) + skippedMessages)

                // Does a DH ratchet when we receive a new public key
                val dhOutputs = KeyRatchet.DiffieHellmanRatchet(this, message.publicKey, targetId)
                receivingKeyMap.put(targetId, KeyRatchet.SymmetricKeyRatchetRoot(this, dhOutputs!!.first, targetId))
                sendingKeyMap.put(targetId, KeyRatchet.SymmetricKeyRatchetRoot(this, dhOutputs.second, targetId))


                // handle skipped messages in the current chain
                if (message.N > 0) {
                    handleSkippedMessages(message.N, targetId)
                    receivingChainLengthMap.put(targetId, message.N)
                }
                sendingChainLengthMap.put(targetId, 0)
            } else {
                // handle skipped messages
                if (message.N > (receivingChainLengthMap.get(targetId) ?: 0)) {
                    handleSkippedMessages(message.N - (receivingChainLengthMap.get(targetId) ?: 0), targetId)
                }
            }

            receivedMessageIdMap.put(targetId, (receivedMessageIdMap.get(targetId)?.plus(1)) ?: 0)
            // generates the new receivingKey
            val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, false, targetId)

            // associatedData = Ephemeral publicKey + public id key Alice + public id Key bob
            val associatedData = message.publicKey + targetPublicKeyMap.get(targetId)!! + preKeysMap.get(targetId)!!.publicIdentityPreKey.encoded

            // decrypt message
            var decryptedString: String? = null
            var timestampBytes: Long? = null

            if (keepStructure) {
                val result = RDFEncryptionProcessor.decryptRDF(
                    String(message.cipherText, Charsets.UTF_8),
                    messageKey,
                    associatedData
                )
                decryptedString = result.first
                timestampBytes = result.second
            } else {
                val decryptedData = aesGcmDecrypt(message.cipherText, messageKey, associatedData)
                decryptedString = String(decryptedData!!.copyOfRange(8, decryptedData.size))
                timestampBytes = ByteBuffer.wrap(decryptedData.copyOfRange(0, 8)).long
            }
            messagesList.add(DecryptedMessage(message.messageId, message.publicKey, decryptedString, timestampBytes))
        }

        return messagesList
    }

    private fun handleSkippedMessages(skippedMessages: Int, targetPod: String) {
        for (i in 1..skippedMessages) {
            val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, false, targetPod)
            skippedKeysMap.get(targetPod)!!.put(receivedMessageIdMap.get(targetPod)?.plus(1) ?: 0, messageKey)
            receivedMessageIdMap.put(targetPod, receivedMessageIdMap.get(targetPod)?.plus(1) ?: 0)
        }
    }
}











