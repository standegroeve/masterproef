package security

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import security.messages.DecryptedMessage
import security.messages.EncryptedMessage
import security.messages.EncryptedMessageString
import security.messages.X3DHPublicKeysAsString
import java.util.*

object messageController {
    private val client = OkHttpClient()

    private val MockedEncryptedMessagesList = mutableListOf<EncryptedMessage>()

    fun sendMessage(senderPodId: String, targetPodId: String, encryptedMessage: EncryptedMessage, authenticationCode: String, mocked: Boolean) {
        if (mocked) {
            MockedEncryptedMessagesList.add(encryptedMessage)
        }
        else {
            val jsonLd = """
            {
                "@context": {
                    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#"
                },
                "kss:messageId": "${encryptedMessage.messageId}",
                "kss:publicKey": "${Base64.getEncoder().encodeToString(encryptedMessage.publicKey)}",
                "kss:cipherText": "${Base64.getEncoder().encodeToString(encryptedMessage.cipherText)}",
                "kss:sequenceNumber": "${encryptedMessage.N}",
                "kss:prevSequenceNumber": "${encryptedMessage.PN}"
            }
        """.trimIndent()

            val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())

            val request = Request.Builder()
                .url("http://localhost:8080/${targetPodId}/messages?senderPodId=${senderPodId}")
                .put(requestBody)
                .header("Content-Type", "application/ld+json")
                .header("Authorization", "Bearer $authenticationCode")
                .build()
            client.newCall(request).execute().use { response ->
                if (response.code != 204) {
                    throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
                }
            }
        }

    }

    fun retrieveMessages(retrieverPodId: String, targetPodId: String, latestReceivedMessageId: Int, skippedKeys: Map<Int, ByteArray>, authenticationCode: String, mocked: Boolean): List<EncryptedMessage> {
        if (mocked) {
            val encryptedMessages = MockedEncryptedMessagesList

            val filteredMessages = encryptedMessages.filter { message ->
                message.messageId > latestReceivedMessageId || skippedKeys.containsKey(message.messageId)
            }

            return filteredMessages.sortedBy { it.messageId }
        }
        else {
            val requestGet = Request.Builder()
                .url("http://localhost:8080/${targetPodId}/messages")
                .get()
                .header("Authorization", "Bearer $authenticationCode")
                .build()

            client.newCall(requestGet).execute().use { response ->
                if (response.code != 200) {
                    throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
                }

                val responseBody = response.body?.string() ?: throw RuntimeException("Response body was null")

                val objectMapper = jacksonObjectMapper()

                val responseMap: Map<String, Any> = objectMapper.readValue(responseBody)

                val key = if (retrieverPodId == targetPodId) "kss:messageInbox" else "kss:messageOutbox"

                val encryptedMessageList = responseMap[key]

                val encryptedMessages = when (encryptedMessageList) {
                    // If it's a list, process each item
                    is List<*> -> {
                        encryptedMessageList.mapNotNull { message ->
                            objectMapper.convertValue(message, EncryptedMessageString::class.java)
                                .convertToEncryptedMessage()
                        }
                    }
                    // If it's a single object (Map), process it
                    is Map<*, *> -> {
                        listOf(
                            objectMapper.convertValue(encryptedMessageList, EncryptedMessageString::class.java)
                                .convertToEncryptedMessage()
                        )
                    }
                    else -> throw RuntimeException("Unexpected data format for 'kss:messageInbox' or 'kss:messageOutbox'")
                }
                val filteredMessages = encryptedMessages.filter { message ->
                    message.messageId > latestReceivedMessageId || skippedKeys.containsKey(message.messageId)
                }
                // Sort the list by messageId
                return filteredMessages.sortedBy { it.messageId }
            }
        }
    }

    fun deleteMessages(targetPodId: String, authCode: String, mocked: Boolean) {
        if (mocked) {
            MockedEncryptedMessagesList.clear()
        }
        else {
            val requestDelete = Request.Builder()
                .url("http://localhost:8080/${targetPodId}/messages")
                .delete()
                .header("Authorization", "Bearer $authCode")
                .build()

            client.newCall(requestDelete).execute().use { response ->
                if (response.code != 204) {
                    throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
                }
            }
        }
    }
}

