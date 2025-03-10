package security

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.util.JSONPObject
import com.fasterxml.jackson.module.kotlin.convertValue
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.util.*
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.apache.kafka.common.protocol.types.Field.Bool
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.crypto.*
import security.messages.*
import java.util.concurrent.TimeUnit


object X3DH {
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

    fun uploadPreKeys(podId: String, preKeys: X3DHPublicPreKeys, authenticationCode: String) {
        val prevPreKeys = getPublicX3DHKeys(podId, authenticationCode)

        var keysToDelete = ""
        if (prevPreKeys != null) {
            keysToDelete = """
                {
                "@id": "ex:$podId",
                "@type": "kss:PublicPreKeys",
                "kss:publicIdentityPreKeyEd25519": "${Base64.getEncoder().encodeToString(prevPreKeys.publicIdentityPreKeyEd25519.encoded)}",
                "kss:publicIdentityPreKeyX25519": "${Base64.getEncoder().encodeToString(prevPreKeys.publicIdentityPreKeyX25519.encoded)}",
                "kss:publicSignedPreKey": "${Base64.getEncoder().encodeToString(prevPreKeys.publicSignedPreKey.encoded)}",
                "kss:publicOneTimePreKeys": "${Base64.getEncoder().encodeToString(prevPreKeys.publicOneTimePreKeys.encoded)}",
                "kss:preKeySignature":  "${Base64.getEncoder().encodeToString(prevPreKeys.preKeySignature)}"
            }
            """.trimIndent()
        }

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
              "kss:delete": [ $keysToDelete ]
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
            println(response.code)
            println(response.message)
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

        // Wait 1 second
        TimeUnit.SECONDS.sleep(1)

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

    fun sendInitialMessage(
        actor: User,
        podId: String,
        preKeys: X3DHPreKeys,
        authenticationCode: String
    ): ByteArray {
        val targetPrekeys: X3DHPublicPreKeys? = getPublicX3DHKeys(podId, authenticationCode)

        if (targetPrekeys == null) {
            println("TargetPreKeys were null")
            throw RuntimeException("TargetPrekeys were null")
        }

        println("keys: $targetPrekeys")

        actor.initialDHPublicKey = targetPrekeys.publicSignedPreKey.encoded
        actor.targetPublicKey = targetPrekeys.publicIdentityPreKeyX25519.encoded
        actor.DHKeyPair = generateX25519KeyPair()
        /*
            Verifiy signature
         */

        val verified = xeddsa_verify(
            targetPrekeys.publicIdentityPreKeyEd25519,
            targetPrekeys.publicSignedPreKey.encoded,
            targetPrekeys.preKeySignature
        )

        if (!verified) {
            println("Verification failed")
            throw RuntimeException("Signature Verification failed")
        }

        /*
            Calculate sharedKey
         */
        val ephemeralKeyPair = generateX25519KeyPair()

        val DH1 = DiffieHellman(preKeys.privateIdentityPreKey, targetPrekeys.publicSignedPreKey)
        val DH2 = DiffieHellman(ephemeralKeyPair.second, X25519PublicKeyParameters(targetPrekeys.publicIdentityPreKeyX25519.encoded))
        val DH3 = DiffieHellman(ephemeralKeyPair.second, targetPrekeys.publicSignedPreKey)

        val F = ByteArray(32) { 0xFF.toByte() }
        val salt = ByteArray(32) { 0x00.toByte() }
        val info = ByteArray(0)

        val oneTimeKeysUsed = 0
        var sharedKey: ByteArray
        if (targetPrekeys.publicOneTimePreKeys == null) {
            sharedKey = HKDF(salt, F + DH1 + DH2 + DH3, info, 32)

        } else {
            val DH4 = DiffieHellman(ephemeralKeyPair.second, targetPrekeys.publicOneTimePreKeys)
//            oneTimeKeysUsed.add(-1)
//            oneTimeKeysUsed.add(0)
            sharedKey = HKDF(salt, F + DH1 + DH2 + DH3 + DH4, info, 32)
        }

        /*
        Generate ciphertext
     */
        val associatedData: ByteArray =
            preKeys.publicIdentityPreKey.encoded + targetPrekeys.publicIdentityPreKeyX25519.encoded
        val plaintext: ByteArray = "Handshake send initial message".toByteArray()
        val ciphertext = aesGcmEncrypt(plaintext, sharedKey, associatedData)


        /*
            Send the initial message
         */

        sendInitialMessageToKvasir(podId, InitialMessage(
            identityPreKey = preKeys.publicIdentityPreKey,
            ephemeralPreKey = ephemeralKeyPair.first,
            preKeyIdentifiers = oneTimeKeysUsed,
            initialCiphertext = ciphertext!!
        ), authenticationCode)

        println("sk1: ${sharedKey[0]}")

        return sharedKey
    }

    fun processInitialMessage(actor: User, podId: String, preKeys: X3DHPreKeys, authenticationCode: String): ByteArray {
        /*
            Fetch the initial message
         */
        val initialMessage = retrieveInitialMessageFromKvasir(podId, authenticationCode)

        if (initialMessage == null) {
            println("InitialMessage was null")
            throw RuntimeException("InitialMessage was null")
        }

        println("initMessage: $initialMessage")

        actor.DHKeyPair = Pair(actor.preKeys!!.publicSignedPrekey, actor.preKeys!!.privateSignedPrekey)

        actor.targetPublicKey = initialMessage.identityPreKey.encoded

        /*
            Calculate sharedKey
         */

        val DH1 = DiffieHellman(preKeys.privateSignedPrekey, initialMessage.identityPreKey)
        val DH2 = DiffieHellman(preKeys.privateIdentityPreKey, initialMessage.ephemeralPreKey)
        val DH3 = DiffieHellman(preKeys.privateSignedPrekey, initialMessage.ephemeralPreKey)

        val F = ByteArray(32) { 0xFF.toByte() }
        val salt = ByteArray(32) { 0x00.toByte() }
        val info = ByteArray(0)

        var sharedKey: ByteArray
        if (initialMessage.preKeyIdentifiers == null) {
            sharedKey = HKDF(salt, F + DH1 + DH2 + DH3, info, 32)

        } else {
            val DH4 = DiffieHellman(preKeys.privateOneTimePrekeys, initialMessage.ephemeralPreKey)
            sharedKey = HKDF(salt, F + DH1 + DH2 + DH3 + DH4, info, 32)
        }

        println("check")
        println("sk2: ${sharedKey[0]}")

        val associatedData: ByteArray = initialMessage.identityPreKey.encoded + preKeys.publicIdentityPreKey.encoded

        val plaintext = aesGcmDecrypt(initialMessage.initialCiphertext, sharedKey, associatedData)

//        if (plaintext != null) {
//            actor.preKeys = actor.preKeys?.let {
//                preKeys.copy(
//                    publicOneTimePrekeys = it.publicOneTimePrekeys.filterIndexed { index, _ -> index !in initialMessage.preKeyIdentifiers },
//                    privateOneTimePrekeys = it.privateOneTimePrekeys.filterIndexed { index, _ -> index !in initialMessage.preKeyIdentifiers }
//                )
//            }
//        }

        /*
            TODO: Update prekeys on server
         */

        return sharedKey
    }

    private fun sendInitialMessageToKvasir(targetPodId: String, initialMessage: InitialMessage, authenticationCode: String) {

        val prevInitialMessage = retrieveInitialMessageFromKvasir(targetPodId, authenticationCode)

        //var initialMessageToDelete = ""
        if (prevInitialMessage != null) {
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
                        "kss:identityPreKey": "${Base64.getEncoder().encodeToString(prevInitialMessage.identityPreKey.encoded)}",
                        "kss:ephemeralPreKey": "${Base64.getEncoder().encodeToString(prevInitialMessage.ephemeralPreKey.encoded)}",
                        "kss:preKeyIdentifiers": "${prevInitialMessage.preKeyIdentifiers.toString()}",
                        "kss:initialCiphertext": "${Base64.getEncoder().encodeToString(prevInitialMessage.initialCiphertext)}"
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
                println("initmessgaemessage: ${response.message}")
                println("code: ${response.code}")
                if (response.code != 201) {
                    throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
                }
            }
//            initialMessageToDelete = """
//                {
//                "@id": "ex:$targetPodId",
//                "@type": "kss:InitialMessage",
//                "kss:identityPreKey": "${Base64.getEncoder().encodeToString(prevInitialMessage.identityPreKey.encoded)}",
//                "kss:ephemeralPreKey": "${Base64.getEncoder().encodeToString(prevInitialMessage.ephemeralPreKey.encoded)}",
//                "kss:preKeyIdentifiers": "${prevInitialMessage.preKeyIdentifiers.toString()}",
//                "kss:initialCiphertext": "${Base64.getEncoder().encodeToString(prevInitialMessage.initialCiphertext)}"
//            }
//            """.trimIndent()
        }

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
                  "kss:ephemeralPreKey": "${Base64.getEncoder().encodeToString(initialMessage.ephemeralPreKey.encoded)}",
                  "kss:preKeyIdentifiers": "${initialMessage.preKeyIdentifiers.toString()}",
                  "kss:initialCiphertext":  "${Base64.getEncoder().encodeToString(initialMessage.initialCiphertext)}"
                }],
              "kss:delete": []
            }
            """.trimIndent()

        println(jsonLd)

        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())

        val request = Request.Builder()
            .url("http://localhost:8080/${targetPodId}/slices/PreKeys/changes")
            .post(requestBody)
            .header("Content-Type", "application/ld+json")
            .header("Authorization", "Bearer $authenticationCode")
            .build()

        client.newCall(request).execute().use { response ->
            println("initmessgaemessage: ${response.message}")
            println("code: ${response.code}")
            if (response.code != 201) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
            return
        }



//        val jsonLd = """
//            {
//                "@context": {
//                    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#"
//                },
//                "kss:identityPreKey": "${Base64.getEncoder().encodeToString(initialMessage.identityPreKey.encoded)}",
//                "kss:ephemeralPreKey": "${Base64.getEncoder().encodeToString(initialMessage.ephemeralPreKey.encoded)}",
//                "kss:preKeyIdentifiers": [${
//                    initialMessage.preKeyIdentifiers.joinToString(", ") {
//                        "\"${
//                            it
//                        }\""
//                    }
//                }],
//                "kss:initialCiphertext": "${Base64.getEncoder().encodeToString(initialMessage.initialCiphertext)}"
//            }
//        """.trimIndent()
//
//        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())
//        val request = Request.Builder()
//            .url("http://localhost:8080/${targetPodId}/initialMessage")
//            .put(requestBody)
//            .header("Content-Type", "application/ld+json")
//            .build()
//        client.newCall(request).execute().use { response ->
//            if (response.code != 204) {
//                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
//            }
//        }
    }

    private fun retrieveInitialMessageFromKvasir(targetPodId: String, authenticationCode: String): InitialMessage? {
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
            println(response.body)
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
            println(initialMessageList)


            val initialMessageString: InitialMessageString = objectMapper.convertValue(
                initialMessageList.firstOrNull()
                    ?: return null
            )

            return initialMessageString.toX25519()
        }




//        val requestGet = Request.Builder()
//            .url("http://localhost:8080/${targetPodId}/initialMessage")
//            .get()
//            .build()
//        client.newCall(requestGet).execute().use { response ->
//            if (response.code != 200) {
//                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
//            }
//            val responseBody = response.body?.string() ?: throw RuntimeException("Response body was null")
//            val objectMapper = jacksonObjectMapper()
//            val initialMessageString = objectMapper.readValue(responseBody, InitialMessageString::class.java)
//            return initialMessageString.toX25519()
//        }
    }
}