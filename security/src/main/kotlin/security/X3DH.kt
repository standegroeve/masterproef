package security

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.util.*
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import security.crypto.*
import security.messages.*


object X3DH {
    private val client = OkHttpClient()

    fun uploadPreKeys(podId: String, preKeys: X3DHPublicPreKeys) {
        val jsonLd = """
        {
            "@context": {
                "kss": "https://kvasir.discover.ilabt.imec.be/vocab#"
            },
            "kss:publicIdentityPreKeyEd25519": "${Base64.getEncoder().encodeToString(preKeys.publicIdentityPreKeyEd25519.encoded)}",
            "kss:publicIdentityPreKeyX25519": "${Base64.getEncoder().encodeToString(preKeys.publicIdentityPreKeyX25519.encoded)}",
            "kss:publicSignedPreKey": "${Base64.getEncoder().encodeToString(preKeys.publicSignedPreKey.encoded)}",
            "kss:publicOneTimePreKeys": [${
            preKeys.publicOneTimePreKeys?.joinToString(", ") {
                "\"${
                    Base64.getEncoder().encodeToString(it.encoded)
                }\""
            }
        }],
            "kss:preKeySignature": "${Base64.getEncoder().encodeToString(preKeys.preKeySignature)}"
        }
    """.trimIndent()

        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())

        val request = Request.Builder()
            .url("http://localhost:8080/${podId}/x3dh")  // Replace with actual endpoint
            .put(requestBody)
            .header("Content-Type", "application/ld+json")
            .build()

        client.newCall(request).execute().use { response ->
            if (response.code != 204) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
        }
    }


    fun getPublicX3DHKeys(podId: String): X3DHPublicPreKeys {
        val requestGet = Request.Builder()
            .url("http://localhost:8080/${podId}/x3dh")
            .get()
            .build()

        client.newCall(requestGet).execute().use { response ->
            if (response.code != 200) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }

            val responseBody = response.body?.string() ?: throw RuntimeException("Response body was null")

            val objectMapper = jacksonObjectMapper()
            val keysAsString = objectMapper.readValue(responseBody, X3DHPublicKeysAsString::class.java)
            return keysAsString.convertToX25519()
        }
    }

    fun sendInitialMessage(
        actor: User,
        podId: String,
        preKeys: X3DHPreKeys
    ): ByteArray {
        val targetPrekeys: X3DHPublicPreKeys = getPublicX3DHKeys(podId)

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

        val oneTimeKeysUsed = mutableListOf<Int>()
        var sharedKey: ByteArray
        if (targetPrekeys.publicOneTimePreKeys == null) {
            sharedKey = HKDF(salt, F + DH1 + DH2 + DH3, info, 32)

        } else {
            val DH4 = DiffieHellman(ephemeralKeyPair.second, targetPrekeys.publicOneTimePreKeys.first())
            oneTimeKeysUsed.add(-1)
            oneTimeKeysUsed.add(0)
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
        Send the Initial Message

        TODO Send the message, now its stored locally for testing
     */
        sendInitialMessageToKvasir(podId, InitialMessage(
            identityPreKey = preKeys.publicIdentityPreKey,
            ephemeralPreKey = ephemeralKeyPair.first,
            preKeyIdentifiers = oneTimeKeysUsed,
            initialCiphertext = ciphertext!!
        ))

        return sharedKey
    }

    fun processInitialMessage(actor: User, podId: String, preKeys: X3DHPreKeys): ByteArray {
        /*
        Fetch initial message
        TODO: Fetch the initial message now its stored locally
     */
        val initialMessage = retrieveInitialMessageFromKvasir(podId)

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
        if (initialMessage.preKeyIdentifiers.isEmpty()) {
            sharedKey = HKDF(salt, F + DH1 + DH2 + DH3, info, 32)

        } else {
            val DH4 = DiffieHellman(preKeys.privateOneTimePrekeys.first(), initialMessage.ephemeralPreKey)
            sharedKey = HKDF(salt, F + DH1 + DH2 + DH3 + DH4, info, 32)
        }

        val associatedData: ByteArray = initialMessage.identityPreKey.encoded + preKeys.publicIdentityPreKey.encoded

        val plaintext = aesGcmDecrypt(initialMessage.initialCiphertext, sharedKey, associatedData)

        if (plaintext != null) {
            actor.preKeys = actor.preKeys?.let {
                preKeys.copy(
                    publicOneTimePrekeys = it.publicOneTimePrekeys.filterIndexed { index, _ -> index !in initialMessage.preKeyIdentifiers },
                    privateOneTimePrekeys = it.privateOneTimePrekeys.filterIndexed { index, _ -> index !in initialMessage.preKeyIdentifiers }
                )
            }
        }

        /*
            TODO: Update prekeys on server
         */

        return sharedKey
    }

    private fun sendInitialMessageToKvasir(targetPodId: String, initialMessage: InitialMessage) {
        val jsonLd = """
            {
                "@context": {
                    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#"
                },
                "kss:identityPreKey": "${Base64.getEncoder().encodeToString(initialMessage.identityPreKey.encoded)}",
                "kss:ephemeralPreKey": "${Base64.getEncoder().encodeToString(initialMessage.ephemeralPreKey.encoded)}",
                "kss:preKeyIdentifiers": [${
                    initialMessage.preKeyIdentifiers.joinToString(", ") {
                        "\"${
                            it
                        }\""
                    }
                }],
                "kss:initialCiphertext": "${Base64.getEncoder().encodeToString(initialMessage.initialCiphertext)}"
            }
        """.trimIndent()

        val requestBody = jsonLd.toRequestBody("application/ld+json".toMediaType())
        val request = Request.Builder()
            .url("http://localhost:8080/${targetPodId}/initialMessage")
            .put(requestBody)
            .header("Content-Type", "application/ld+json")
            .build()
        client.newCall(request).execute().use { response ->
            if (response.code != 204) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
        }
    }

    private fun retrieveInitialMessageFromKvasir(targetPodId: String): InitialMessage {
        val requestGet = Request.Builder()
            .url("http://localhost:8080/${targetPodId}/initialMessage")
            .get()
            .build()
        client.newCall(requestGet).execute().use { response ->
            if (response.code != 200) {
                throw RuntimeException("Unexpected response code: ${response.code}, Message: ${response.message}")
            }
            val responseBody = response.body?.string() ?: throw RuntimeException("Response body was null")
            val objectMapper = jacksonObjectMapper()
            val initialMessageString = objectMapper.readValue(responseBody, InitialMessageString::class.java)
            return initialMessageString.toX25519()
        }
    }
}