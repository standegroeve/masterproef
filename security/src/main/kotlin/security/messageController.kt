package security

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import security.messages.EncryptedMessage
import security.messages.EncryptedMessageString
import java.util.*

object messageController {
    private val client = OkHttpClient()

    fun sendMessage(hashedPodId: String, targetPodId: String, encryptedMessage: EncryptedMessage, authenticationCode: String) {
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
            .url("http://localhost:8080/${targetPodId}/messages?hashedPodId=${hashedPodId}")
            .post(requestBody)
            .header("Content-Type", "application/ld+json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()
        client.newCall(request).execute().use { response ->
            if (response.code != 204) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
        }
    }

    fun retrieveMessages(hashedPodId: String, targetPodId: String, latestReceivedMessageId: Int, skippedKeys: Map<Int, ByteArray>, authenticationCode: String): List<EncryptedMessage> {
        val requestGet = Request.Builder()
            .url("http://localhost:8080/${targetPodId}/messages?hashedPodId=${hashedPodId}")
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

            val encryptedMessageList = responseMap["kss:messageInbox"]

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
                else -> throw RuntimeException("Unexpected data format for kss:messageInbox")
            }
            val filteredMessages = encryptedMessages.filter { message ->
                message.messageId > latestReceivedMessageId || skippedKeys.containsKey(message.messageId)
            }
            // Sort the list by messageId
            return filteredMessages.sortedBy { it.messageId }
        }
    }
}

