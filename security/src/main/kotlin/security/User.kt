package security

import org.apache.jena.rdf.model.Statement
import org.apache.kafka.shaded.com.google.protobuf.Timestamp
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.crypto.DiffieHellman
import security.crypto.aesGcmDecrypt
import security.crypto.aesGcmEncrypt
import security.crypto.generateX25519KeyPair
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

    // Out-of-order message handling
    var skippedKeysMap: MutableMap<String, MutableMap<Int, ByteArray>> = mutableMapOf()
    var sendingChainLengthMap: MutableMap<String, Int> = mutableMapOf()
    var receivingChainLengthMap: MutableMap<String, Int> = mutableMapOf()
    var PNMap: MutableMap<String, Int> = mutableMapOf()
    var sentMessageIdMap: MutableMap<String, Int> = mutableMapOf()
    var receivedMessageIdMap: MutableMap<String, Int> = mutableMapOf()

    var latestReceivedMessageIdMap: MutableMap<String, Int> = mutableMapOf()

    fun sendInitialMessage(targetPod: String, input: ByteArray, timestampBytes: ByteArray, authenticationCode: String, keepStructure: Boolean, valuesToEncrypt: List<String> = emptyList(), tripleGroupsToEncrypt: List<List<Statement>> = emptyList()): String {
        DHKeyPairMap.put(targetPod, generateX25519KeyPair())
        val initialDHoutput = DiffieHellman(DHKeyPairMap.get(targetPod)!!.second, X25519PublicKeyParameters(initialDHPublicKeyMap.get(targetPod)))
        sendingKeyMap.put(targetPod, KeyRatchet.SymmetricKeyRatchetRoot(this, initialDHoutput, targetPod))
        return sendMessage(targetPod, input, timestampBytes, authenticationCode, keepStructure, valuesToEncrypt, tripleGroupsToEncrypt)
    }

    fun sendMessage(targetPod: String, input: ByteArray, timestampBytes: ByteArray, authenticationCode: String, keepStructure: Boolean, valuesToEncrypt: List<String> = emptyList(), tripleGroupsToEncrypt: List<List<Statement>> = emptyList()): String {
        val messageId = sentMessageIdMap.get(targetPod) ?: -1
        sentMessageIdMap.put(targetPod, sentMessageIdMap.get(targetPod)?.plus(1) ?: 0)

        val sequenceNumber = sendingChainLengthMap.get(targetPod) ?: 0

        // generates the new sendingKey
        val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, true, targetPod)

        // associatedData = Ephemeral publicKey + public id key Alice + public id Key bob
        val associatedData = DHKeyPairMap.get(targetPod)!!.first.encoded + preKeysMap.get(targetPod)!!.publicIdentityPreKey.encoded + targetPublicKeyMap.get(targetPod)!!

        // encrypt message
        var ciphertext: Any? = null
        if (keepStructure) {
            ciphertext = RDFEncryptionProcessor.encryptRDF(String(input, Charsets.UTF_8), timestampBytes, messageKey, associatedData, valuesToEncrypt, tripleGroupsToEncrypt).toByteArray()
        }
        else {
            ciphertext = aesGcmEncrypt(timestampBytes + input, messageKey, associatedData)
        }
        val encrpytedMessage = EncryptedMessage(messageId!! + 1, DHKeyPairMap.get(targetPod)!!.first.encoded, ciphertext as ByteArray, sequenceNumber, PNMap.get(targetPod) ?: 0)

        // sends the message to the pod
        messageController.sendMessage(podId, targetPod, encrpytedMessage, authenticationCode)

        println("$targetPod key: ${Base64.getEncoder().encodeToString(messageKey)}")
        println("$targetPod AD: ${Base64.getEncoder().encodeToString(associatedData)}")


        return String(ciphertext, Charsets.UTF_8)
    }

    fun receiveMessage(podToTry: String, authenticationCode: String, keepStructure: Boolean): List<DecryptedMessage> {
        val backUp = this.copy()

        try {
            // Retreive messages which we havent seen already or whose key isnt in skippedKeys
            val encryptedMessages = messageController.retrieveMessages(podId, (latestReceivedMessageIdMap.get(podToTry) ?: -1), skippedKeysMap.get(podToTry) ?: mutableMapOf<Int, ByteArray>(), authenticationCode)

            println("enc: $encryptedMessages")

            var messagesList = mutableListOf<DecryptedMessage>()
            for (i in 0..encryptedMessages.size-1) {
                val message = encryptedMessages[i]

                if (message.messageId > (latestReceivedMessageIdMap.get(podToTry) ?: -1))
                    latestReceivedMessageIdMap.put(podToTry, message.messageId)

                println("check1")

                // Check if messageKey was skipped previously
                if (message.messageId  <= (receivedMessageIdMap.get(podToTry) ?: -1)) {
                    // get earlier determined messageKey and remove it from the map
                    val messageKey = skippedKeysMap.get(podToTry)!!.get(message.messageId)
                    skippedKeysMap.get(podToTry)!!.remove(message.messageId)

                    val associatedData = message.publicKey + targetPublicKeyMap.get(podToTry)!! + preKeysMap.get(podToTry)!!.publicIdentityPreKey.encoded

                    // decrypt message
                    var decryptedString: String?
                    var timestampBytes: Long?

                    if (keepStructure) {
                        val result = RDFEncryptionProcessor.decryptRDF(String(message.cipherText, Charsets.UTF_8), messageKey!!, associatedData)
                        decryptedString = result.first
                        timestampBytes = result.second
                    }
                    else {
                        val decryptedData = aesGcmDecrypt(message.cipherText, messageKey!!, associatedData)
                        decryptedString = String(decryptedData!!.copyOfRange(8, decryptedData.size))
                        timestampBytes = ByteBuffer.wrap(decryptedData.copyOfRange(0, 8)).long
                    }
                    messagesList.add(DecryptedMessage(message.messageId, message.publicKey, decryptedString, timestampBytes))
                    continue
                }

                println("check2")



                if (!message.publicKey.contentEquals(prevPublicKeyMap.get(podToTry))) {
                    // handle skipped messages in the previous chain
                    val skippedMessages = (message.PN - (receivingChainLengthMap.get(podToTry) ?: 0)).takeIf { message.PN > (receivingChainLengthMap.get(podToTry) ?: -1) } ?: 0
                    if (message.PN > receivingChainLengthMap.get(podToTry) ?: 0) {
                        handleSkippedMessages(skippedMessages, podToTry)
                    }

                    println("check3")


                    PNMap.put(podToTry, (sendingChainLengthMap.get(podToTry) ?: 0) + skippedMessages)

                    // Does a DH ratchet when we receive a new public key
                    val dhOutputs = KeyRatchet.DiffieHellmanRatchet(this, message.publicKey, podToTry)
                    receivingKeyMap.put(podToTry, KeyRatchet.SymmetricKeyRatchetRoot(this, dhOutputs!!.first, podToTry))
                    sendingKeyMap.put(podToTry, KeyRatchet.SymmetricKeyRatchetRoot(this, dhOutputs.second, podToTry))


                    // handle skipped messages in the current chain
                    if (message.N > 0) {
                        handleSkippedMessages(message.N, podToTry)
                        receivingChainLengthMap.put(podToTry, message.N)
                    }
                    sendingChainLengthMap.put(podToTry, 0)
                }
                else {
                    // handle skipped messages
                    if (message.N > (receivingChainLengthMap.get(podToTry) ?: 0)) {
                        handleSkippedMessages(message.N - (receivingChainLengthMap.get(podToTry) ?: 0), podToTry)
                    }
                }

                println("check4")
                println(preKeysMap)

                receivedMessageIdMap.put(podToTry, receivedMessageIdMap.get(podToTry)?.plus(1) ?: 0)
                // generates the new receivingKey
                val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, false, podToTry)

                // associatedData = Ephemeral publicKey + public id key Alice + public id Key bob
                val associatedData = message.publicKey + targetPublicKeyMap.get(podToTry)!! + preKeysMap.get(podId)!!.publicIdentityPreKey.encoded

                println("podtoTry: $podToTry")
                println("$podId key: ${Base64.getEncoder().encodeToString(messageKey)}")
                println("$podId AD: ${Base64.getEncoder().encodeToString(associatedData)}")

                // decrypt message
                var decryptedString: String? = null
                var timestampBytes: Long? = null

                if (keepStructure) {
                    val result = RDFEncryptionProcessor.decryptRDF(String(message.cipherText, Charsets.UTF_8), messageKey, associatedData)
                    decryptedString = result.first
                    timestampBytes = result.second
                }
                else {
                    val decryptedData = aesGcmDecrypt(message.cipherText, messageKey, associatedData)
                    decryptedString = String(decryptedData!!.copyOfRange(8, decryptedData.size))
                    timestampBytes = ByteBuffer.wrap(decryptedData.copyOfRange(0, 8)).long
                }

                println("check5")


                messagesList.add(DecryptedMessage(message.messageId, message.publicKey, decryptedString, timestampBytes))
            }

            println("check6 : $messagesList")


            return messagesList
        }
        catch (e: Exception) {
            restoreFrom(backUp)
            println(e)
            throw Error("Not the right sender or something else went wrong: $e")
        }
    }

    private fun handleSkippedMessages(skippedMessages: Int, targetPod: String) {
        for (i in 1..skippedMessages) {
            val messageKey = KeyRatchet.SymmetricKeyRatchetNonRoot(this, false, targetPod)
            skippedKeysMap.get(targetPod)!!.put(receivedMessageIdMap.get(targetPod)?.plus(1) ?: 0, messageKey)
            receivedMessageIdMap.put(targetPod, receivedMessageIdMap.get(targetPod)?.plus(1) ?: 0)
        }
    }


    private fun copy(): User {
        val copy = User(podId)

        fun <K, V> MutableMap<K, V>.copyValues(): MutableMap<K, V> =
            this.mapValues { (_, v) -> v }.toMutableMap()

        fun MutableMap<String, ByteArray>.copyByteArrays(): MutableMap<String, ByteArray> =
            this.mapValues { (_, v) -> v.copyOf() }.toMutableMap()

        fun MutableMap<String, MutableMap<Int, ByteArray>>.copyNestedByteArrays(): MutableMap<String, MutableMap<Int, ByteArray>> =
            this.mapValues { (_, innerMap) ->
                innerMap.mapValues { it.value.copyOf() }.toMutableMap()
            }.toMutableMap()

        copy.initialDHPublicKeyMap = initialDHPublicKeyMap.copyByteArrays()
        copy.targetPublicKeyMap = targetPublicKeyMap.copyByteArrays()
        copy.preKeysMap = preKeysMap.copyValues() // Make sure X3DHPreKeys is immutable or cloneable

        copy.sharedKeysMap.putAll(sharedKeysMap.copyByteArrays())
        copy.sendingKeyMap = sendingKeyMap.copyByteArrays()
        copy.receivingKeyMap = receivingKeyMap.copyByteArrays()
        copy.prevPublicKeyMap = prevPublicKeyMap.copyByteArrays()

        copy.DHKeyPairMap = DHKeyPairMap.mapValues { (_, pair) ->
            Pair(pair.first, pair.second) // assumes these are immutable or thread-safe references
        }.toMutableMap()

        copy.skippedKeysMap = skippedKeysMap.copyNestedByteArrays()

        copy.sendingChainLengthMap = sendingChainLengthMap.copyValues()
        copy.receivingChainLengthMap = receivingChainLengthMap.copyValues()
        copy.PNMap = PNMap.copyValues()
        copy.sentMessageIdMap = sentMessageIdMap.copyValues()
        copy.receivedMessageIdMap = receivedMessageIdMap.copyValues()
        copy.latestReceivedMessageIdMap = latestReceivedMessageIdMap.copyValues()

        return copy
    }

    private fun restoreFrom(other: User) {
        this.initialDHPublicKeyMap = other.initialDHPublicKeyMap.mapValues { it.value.copyOf() }.toMutableMap()
        this.targetPublicKeyMap = other.targetPublicKeyMap.mapValues { it.value.copyOf() }.toMutableMap()
        this.preKeysMap = other.preKeysMap.toMutableMap()
        this.sharedKeysMap.clear(); this.sharedKeysMap.putAll(other.sharedKeysMap.mapValues { it.value.copyOf() })
        this.sendingKeyMap = other.sendingKeyMap.mapValues { it.value.copyOf() }.toMutableMap()
        this.receivingKeyMap = other.receivingKeyMap.mapValues { it.value.copyOf() }.toMutableMap()
        this.prevPublicKeyMap = other.prevPublicKeyMap.mapValues { it.value.copyOf() }.toMutableMap()
        this.DHKeyPairMap = other.DHKeyPairMap.toMutableMap()
        this.skippedKeysMap = other.skippedKeysMap.mapValues { it.value.toMutableMap() }.toMutableMap()
        this.sendingChainLengthMap = other.sendingChainLengthMap.toMutableMap()
        this.receivingChainLengthMap = other.receivingChainLengthMap.toMutableMap()
        this.PNMap = other.PNMap.toMutableMap()
        this.sentMessageIdMap = other.sentMessageIdMap.toMutableMap()
        this.receivedMessageIdMap = other.receivedMessageIdMap.toMutableMap()
        this.latestReceivedMessageIdMap = other.latestReceivedMessageIdMap.toMutableMap()
    }
}











