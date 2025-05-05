package security.APIControllers

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.util.JSONPObject
import com.fasterxml.jackson.module.kotlin.convertValue
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import security.messages.InitialMessage
import security.messages.InitialMessageString
import security.messages.X3DHPublicKeysAsString
import security.messages.X3DHPublicPreKeys
import java.util.*

object X3DHController {
    private val client = OkHttpClient()

    fun initiateSliceSchema(podId: String, authenticationCode: String) {
        val jsonLd = """
            {
                "@context": {
                    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#"
                },
                "kss:name": "PreKeys",
                "kss:description": "Schema for storing public pre-keys",
                "kss:schema": "type Query { publicPreKeys: [kss_PublicPreKeys!]! initialMessages: [kss_InitialMessage!]! } type kss_PublicPreKeys { id: ID! kss_publicIdentityPreKeyEd25519: String! kss_publicIdentityPreKeyX25519: String! kss_publicSignedPreKey: String! kss_publicOneTimePreKeys: String! kss_preKeySignature: String! } type kss_InitialMessage { id: ID! kss_identityPreKey: String! kss_ephemeralPreKey: String! kss_preKeyIdentifiers: String! kss_initialCiphertext: String! } type Mutation { addPublicPreKeys(publicPreKeys: [PublicPreKeysInput!]!): ID! addInitialMessage(initialMessage: [InitialMessageInput!]!): ID! removePublicPreKeys(publicPreKeys: [PublicPreKeysInput!]!): ID! removeInitialMessage(initialMessage: [InitialMessageInput!]!): ID! } input PublicPreKeysInput @class(iri: \"kss:PublicPreKeys\") { id: ID! kss_publicIdentityPreKeyEd25519: String! kss_publicIdentityPreKeyX25519: String! kss_publicSignedPreKey: String! kss_publicOneTimePreKeys: String! kss_preKeySignature: String! } input InitialMessageInput @class(iri: \"kss:InitialMessage\") { id: ID! kss_identityPreKey: String! kss_ephemeralPreKey: String! kss_preKeyIdentifiers: String! kss_initialCiphertext: String! }"
            }
        """.trimIndent()

        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())

        val request = Request.Builder()
            .url("http://localhost:8080/${podId}/slices")
            .post(requestBody)
            .header("Content-Type", "application/ld+json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code == 409) {
                println("Conflict: schema already created")
                return;
            }
            if (response.code != 201) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
            return
        }
    }


    fun getPublicX3DHKeys(podId: String, authenticationCode: String): X3DHPublicPreKeys? {
        val json = """
            { "query": "{ publicPreKeys @filter(if: \"id==http://example.org/$podId\") { id kss_publicIdentityPreKeyEd25519 kss_publicIdentityPreKeyX25519 kss_publicSignedPreKey kss_publicOneTimePreKeys kss_preKeySignature } }" }
            """.trimIndent()


        val requestBody = json.toRequestBody("application/json".toMediaType())

        val requestPost = Request.Builder()
            .url("http://localhost:8080/${podId}/slices/PreKeys/query")
            .post(requestBody)
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(requestPost).execute().use { response ->
            if (response.code != 200) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }

            val responseBody = response.body?.string() ?: throw RuntimeException("Response body was null")

            val objectMapper = jacksonObjectMapper()

            // Deserialize JSON into a generic Map
            val keysAsMap: Map<String, Any> = objectMapper.readValue(responseBody)

            // Extract "publicPreKeys" list safely
            val publicPreKeys = (keysAsMap.get("data") as? Map<String, Any>)
                ?.get("publicPreKeys") as? List<Map<String, Any>>
                ?: return null

            val X3dhKeysAsString: X3DHPublicKeysAsString = objectMapper.convertValue(publicPreKeys.firstOrNull()
                ?: return null
            )

            return X3dhKeysAsString.convertToX25519()
        }
    }

    fun postX3DHPreKeys(podId: String, preKeys: X3DHPublicPreKeys, authenticationCode: String) {
        val jsonLd = """
            {
              "@context": {
                  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
            	  "ex": "http://example.org/"
              },
              "kss:insert": [{
            	"@id": "ex:$podId",
                  "@type": "kss:PublicPreKeys",
                  "kss:publicIdentityPreKeyEd25519": "${Base64.getEncoder().encodeToString(preKeys.publicIdentityPreKeyEd25519.encoded)}",
                  "kss:publicIdentityPreKeyX25519": "${Base64.getEncoder().encodeToString(preKeys.publicIdentityPreKeyX25519.encoded)}",
                  "kss:publicSignedPreKey": "${Base64.getEncoder().encodeToString(preKeys.publicSignedPreKey.encoded)}",
                  "kss:publicOneTimePreKeys": "${Base64.getEncoder().encodeToString(preKeys.publicOneTimePreKeys.encoded)}",
                  "kss:preKeySignature":  "${Base64.getEncoder().encodeToString(preKeys.preKeySignature)}"
                }],
              "kss:delete": []
            }
            """.trimIndent()

        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())

        val request = Request.Builder()
            .url("http://localhost:8080/${podId}/slices/PreKeys/changes")
            .post(requestBody)
            .header("Content-Type", "application/ld+json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code != 201) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
            return
        }
    }

    fun postAndDeleteX3DHPreKeys(podId: String, prevPreKeys: X3DHPublicPreKeys, preKeys: X3DHPublicPreKeys, authenticationCode: String) {
        val jsonLd = """
            {
              "@context": {
                  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
            	  "ex": "http://example.org/"
              },
              "kss:insert": [{
            	"@id": "ex:$podId",
                  "@type": "kss:PublicPreKeys",
                  "kss:publicIdentityPreKeyEd25519": "${Base64.getEncoder().encodeToString(preKeys.publicIdentityPreKeyEd25519.encoded)}",
                  "kss:publicIdentityPreKeyX25519": "${Base64.getEncoder().encodeToString(preKeys.publicIdentityPreKeyX25519.encoded)}",
                  "kss:publicSignedPreKey": "${Base64.getEncoder().encodeToString(preKeys.publicSignedPreKey.encoded)}",
                  "kss:publicOneTimePreKeys": "${Base64.getEncoder().encodeToString(preKeys.publicOneTimePreKeys.encoded)}",
                  "kss:preKeySignature":  "${Base64.getEncoder().encodeToString(preKeys.preKeySignature)}"
                }],
              "kss:delete": [{
                "@id": "ex:$podId",
                "@type": "kss:PublicPreKeys",
                "kss:publicIdentityPreKeyEd25519": "${Base64.getEncoder().encodeToString(prevPreKeys.publicIdentityPreKeyEd25519.encoded)}",
                "kss:publicIdentityPreKeyX25519": "${Base64.getEncoder().encodeToString(prevPreKeys.publicIdentityPreKeyX25519.encoded)}",
                "kss:publicSignedPreKey": "${Base64.getEncoder().encodeToString(prevPreKeys.publicSignedPreKey.encoded)}",
                "kss:publicOneTimePreKeys": "${Base64.getEncoder().encodeToString(prevPreKeys.publicOneTimePreKeys.encoded)}",
                "kss:preKeySignature":  "${Base64.getEncoder().encodeToString(prevPreKeys.preKeySignature)}"
            } ]
            }
            """.trimIndent()

        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())

        val request = Request.Builder()
            .url("http://localhost:8080/${podId}/slices/PreKeys/changes")
            .post(requestBody)
            .header("Content-Type", "application/ld+json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code != 201) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
            return
        }
    }

    fun retrieveInitialMessageFromKvasir(targetPodId: String, authenticationCode: String): InitialMessage? {
        val json = """
            { "query": "{ initialMessages @filter(if: \"id==http://example.org/$targetPodId\") { id kss_identityPreKey kss_ephemeralPreKey kss_preKeyIdentifiers kss_initialCiphertext } }" }
            """.trimIndent()

        val requestBody = json.toRequestBody("application/json".toMediaType())

        val requestPost = Request.Builder()
            .url("http://localhost:8080/${targetPodId}/slices/PreKeys/query")
            .post(requestBody)
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(requestPost).execute().use { response ->
            if (response.code != 200) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }

            val responseBody = response.body?.string() ?: throw RuntimeException("Response body was null")

            val objectMapper = jacksonObjectMapper()

            // Deserialize JSON into a generic Map
            val keysAsMap: Map<String, Any> = objectMapper.readValue(responseBody)

            // Extract "messages" list safely
            val initialMessageList = (keysAsMap.get("data") as? Map<String, Any>)
                ?.get("initialMessages") as? List<Map<String, Any>>
                ?: return null


            val initialMessageString: InitialMessageString = objectMapper.convertValue(
                initialMessageList.firstOrNull()
                    ?: return null
            )

            return initialMessageString.toX25519()
        }
    }

    fun sendInitialMessageToKvasir(targetPodId: String, initialMessage: InitialMessage, authenticationCode: String) {
        // send a new initial message
        val jsonLd = """
            {
              "@context": {
                  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
            	  "ex": "http://example.org/"
              },
              "kss:insert": [{
            	  "@id": "ex:$targetPodId",
                  "@type": "kss:InitialMessage",
                  "kss:identityPreKey": "${Base64.getEncoder().encodeToString(initialMessage.identityPreKey.encoded)}",
                  "kss:ephemeralPreKey": "${
            Base64.getEncoder().encodeToString(initialMessage.ephemeralPreKey.encoded)
        }",
                  "kss:preKeyIdentifiers": "${initialMessage.preKeyIdentifiers.toString()}",
                  "kss:initialCiphertext":  "${Base64.getEncoder().encodeToString(initialMessage.initialCiphertext)}"
                }],
              "kss:delete": []
            }
            """.trimIndent()

        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())

        val request = Request.Builder()
            .url("http://localhost:8080/${targetPodId}/slices/PreKeys/changes")
            .post(requestBody)
            .header("Content-Type", "application/ld+json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code != 201) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
            return
        }
    }

    fun sendAndDeleteInitialMessageToKvasir(targetPodId: String, initialMessage: InitialMessage, authenticationCode: String) {

        // If an initial message already exist with same podId, fetch it
        val prevInitialMessage = retrieveInitialMessageFromKvasir(targetPodId, authenticationCode)!!

        // If a message already exists with same podId, delete it

        val jsonLdDelete = """
             {
                  "@context": {
                      "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
                      "ex": "http://example.org/"
             },
             "kss:insert": [],
             "kss:delete": [ {
                      "@id": "ex:$targetPodId",
                      "@type": "kss:InitialMessage",
                      "kss:identityPreKey": "${
                          Base64.getEncoder().encodeToString(prevInitialMessage.identityPreKey.encoded)
                      }",
                      "kss:ephemeralPreKey": "${
                          Base64.getEncoder().encodeToString(prevInitialMessage.ephemeralPreKey.encoded)
                      }",
                      "kss:preKeyIdentifiers": "${prevInitialMessage.preKeyIdentifiers.toString()}",
                      "kss:initialCiphertext": "${
                          Base64.getEncoder().encodeToString(prevInitialMessage.initialCiphertext)
                      }"
                } ]
             }
             """.trimIndent()

        val requestBodyDelete = jsonLdDelete.toRequestBody("application/ld+json".toMediaType())

        val requestDelete = Request.Builder()
            .url("http://localhost:8080/${targetPodId}/slices/PreKeys/changes")
            .post(requestBodyDelete)
            .header("Content-Type", "application/ld+json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(requestDelete).execute().use { response ->
            if (response.code != 201) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
        }

        // send a new initial message
        val jsonLd = """
            {
              "@context": {
                  "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
            	  "ex": "http://example.org/"
              },
              "kss:insert": [{
            	  "@id": "ex:$targetPodId",
                  "@type": "kss:InitialMessage",
                  "kss:identityPreKey": "${Base64.getEncoder().encodeToString(initialMessage.identityPreKey.encoded)}",
                  "kss:ephemeralPreKey": "${
            Base64.getEncoder().encodeToString(initialMessage.ephemeralPreKey.encoded)
        }",
                  "kss:preKeyIdentifiers": "${initialMessage.preKeyIdentifiers.toString()}",
                  "kss:initialCiphertext":  "${Base64.getEncoder().encodeToString(initialMessage.initialCiphertext)}"
                }],
              "kss:delete": []
            }
            """.trimIndent()

        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())

        val request = Request.Builder()
            .url("http://localhost:8080/${targetPodId}/slices/PreKeys/changes")
            .post(requestBody)
            .header("Content-Type", "application/ld+json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code != 201) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
            return
        }
    }
}
