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
import security.APIControllers.X3DHController
import security.APIControllers.X3DHController.getPublicX3DHKeys
import security.APIControllers.X3DHController.postAndDeleteX3DHPreKeys
import security.APIControllers.X3DHController.postX3DHPreKeys
import security.APIControllers.X3DHController.retrieveInitialMessageFromKvasir
import security.APIControllers.X3DHController.sendAndDeleteInitialMessageToKvasir
import security.APIControllers.X3DHController.sendInitialMessageToKvasir
import security.crypto.*
import security.messages.*
import java.util.concurrent.TimeUnit
import security.crypto.KeyUtils.generateX25519KeyPair
import security.crypto.CryptoUtils.aesGcmEncrypt
import security.crypto.CryptoUtils.aesGcmDecrypt
import security.crypto.CryptoUtils.DiffieHellman
import security.crypto.CryptoUtils.HKDF
import security.crypto.XEdDSA.xeddsa_verify
import java.security.MessageDigest

object X3DH {

    /*
        Initiates the schema to perform queries and mutations to the publicPreKeys and for the initialMessages
     */
    fun initiateSliceSchema(podId: String, authenticationCode: String) {
        X3DHController.initiateSliceSchema(podId, authenticationCode)
    }

    /*
        Deletes existing prekeys (if any exist with same podId) and uploads new ones
     */
    fun uploadPreKeys(podId: String, preKeys: X3DHPublicPreKeys, authenticationCode: String) {
        // If preKeys already exist with same podId, fetch them
        val prevPreKeys = getPublicX3DHKeys(podId, authenticationCode)

        if (prevPreKeys == null) {
            postX3DHPreKeys(podId, preKeys, authenticationCode)
        }
        else {
            postAndDeleteX3DHPreKeys(podId, prevPreKeys, preKeys, authenticationCode)
        }
    }

    /*
        Fetch the publicX3DHKeys from a pod
     */

    /*
        Do the DH-calculations to make and send the initial message
     */
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

        actor.initialDHPublicKey = targetPrekeys.publicSignedPreKey.encoded
        actor.targetPublicKey = targetPrekeys.publicIdentityPreKeyX25519.encoded
        actor.DHKeyPair = generateX25519KeyPair()

        // Verify the signature
        val verified = xeddsa_verify(
            targetPrekeys.publicIdentityPreKeyEd25519,
            targetPrekeys.publicSignedPreKey.encoded,
            targetPrekeys.preKeySignature
        )

        if (!verified) {
            println("Verification failed")
            throw RuntimeException("Signature Verification failed")
        }

        // Calculate the sharedKey
        val ephemeralKeyPair = generateX25519KeyPair()

        val DH1 = DiffieHellman(preKeys.privateIdentityPreKey, targetPrekeys.publicSignedPreKey)
        val DH2 = DiffieHellman(
            ephemeralKeyPair.second,
            X25519PublicKeyParameters(targetPrekeys.publicIdentityPreKeyX25519.encoded)
        )
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

        val prevInitialMessage = retrieveInitialMessageFromKvasir(podId, authenticationCode)

        if (prevInitialMessage == null) {
            sendInitialMessageToKvasir(
                podId, InitialMessage(
                    identityPreKey = preKeys.publicIdentityPreKey,
                    ephemeralPreKey = ephemeralKeyPair.first,
                    preKeyIdentifiers = oneTimeKeysUsed,
                    initialCiphertext = ciphertext!!
                ), authenticationCode
            )
        }
        else {
            sendAndDeleteInitialMessageToKvasir(
                podId, InitialMessage(
                    identityPreKey = preKeys.publicIdentityPreKey,
                    ephemeralPreKey = ephemeralKeyPair.first,
                    preKeyIdentifiers = oneTimeKeysUsed,
                    initialCiphertext = ciphertext!!
                ), authenticationCode
            )
        }

        val digest = MessageDigest.getInstance("SHA-256")
        val hashed = digest.digest(preKeys.publicIdentityPreKey.encoded)
        actor.hashedPodId = Base64.getUrlEncoder().withoutPadding().encodeToString(hashed)

        val digestTarget = MessageDigest.getInstance("SHA-256")
        val hashedTarget = digestTarget.digest(targetPrekeys.publicIdentityPreKeyX25519.encoded)
        actor.targetHashedPodId = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedTarget)

        return sharedKey
    }


    /*
        Fetch and process the initial message
     */
    fun processInitialMessage(actor: User, podId: String, preKeys: X3DHPreKeys, authenticationCode: String): ByteArray {
        /*
            Fetch the initial message
         */
        val initialMessage = retrieveInitialMessageFromKvasir(podId, authenticationCode)

        if (initialMessage == null) {
            println("InitialMessage was null")
            throw RuntimeException("InitialMessage was null")
        }

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


        val associatedData: ByteArray = initialMessage.identityPreKey.encoded + preKeys.publicIdentityPreKey.encoded

        val plaintext = aesGcmDecrypt(initialMessage.initialCiphertext, sharedKey, associatedData)

        if (!plaintext.contentEquals("Handshake send initial message".toByteArray())) {
            println("Initial message decryption failed")
            throw RuntimeException("Initial message decryption failed")
        }

        val digest = MessageDigest.getInstance("SHA-256")
        val hashed = digest.digest(preKeys.publicIdentityPreKey.encoded)
        actor.hashedPodId = Base64.getUrlEncoder().withoutPadding().encodeToString(hashed)

        val digestTarget = MessageDigest.getInstance("SHA-256")
        val hashedTarget = digestTarget.digest(initialMessage.identityPreKey.encoded)
        actor.targetHashedPodId = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedTarget)

        return sharedKey
    }
}