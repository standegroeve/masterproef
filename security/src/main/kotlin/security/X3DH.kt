package security

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import io.quarkus.logging.Log
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.bouncycastle.crypto.KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.security.SecureRandom
import java.util.*
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

fun generateX25519KeyPair(): Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters> {
    val secureRandom = SecureRandom()
    // Key generation parameters
    val keyGenParams = KeyGenerationParameters(secureRandom, 256)
    val keyPairGenerator = org.bouncycastle.crypto.generators.X25519KeyPairGenerator()
    keyPairGenerator.init(keyGenParams)
    val keyPair = keyPairGenerator.generateKeyPair()
    val privateKey = keyPair.private as X25519PrivateKeyParameters
    val publicKey = keyPair.public as X25519PublicKeyParameters
    return Pair(publicKey, privateKey)
}

fun generatePrekeys(): X3DHPreKeys {
    val identityKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters> = generateX25519KeyPair()
    val signedPreKeyPair: Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters> = generateX25519KeyPair()
    val signature: ByteArray = xeddsa_sign(identityKeyPair.second, signedPreKeyPair.first.encoded)
    // create a list with one-time keyPairs
    val oneTimePreKeyPairs: List<Pair<X25519PublicKeyParameters, X25519PrivateKeyParameters>> = (1..5).map {
        generateX25519KeyPair()
    }
    return X3DHPreKeys(
        identityKeyPair.first,
        signedPreKeyPair.first,
        oneTimePreKeyPairs.map { it.first },
        signature,
        identityKeyPair.second,
        signedPreKeyPair.second,
        oneTimePreKeyPairs.map { it.second },
    )
}

data class X3DHPreKeys(
    val publicIdentityPreKey: X25519PublicKeyParameters,
    val publicSignedPrekey: X25519PublicKeyParameters,
    val publicOneTimePrekeys: List<X25519PublicKeyParameters>,
    val preKeySignature: ByteArray,
    val privateIdentityPreKey: X25519PrivateKeyParameters,
    val privateSignedPrekey: X25519PrivateKeyParameters,
    val privateOneTimePrekeys: List<X25519PrivateKeyParameters>
) {
    fun getPublic(): X3DHPublicPreKeys {
        return X3DHPublicPreKeys(publicIdentityPreKey, publicSignedPrekey, publicOneTimePrekeys, preKeySignature)
    }
}

data class X3DHPublicPreKeys(
    val publicIdentityPreKey: X25519PublicKeyParameters,
    val publicSignedPrekey: X25519PublicKeyParameters,
    val publicOneTimePrekeys: List<X25519PublicKeyParameters>,
    val preKeySignature: ByteArray
)

@JsonIgnoreProperties(ignoreUnknown = true)
data class X3DHPublicKeysAsString(
    @JsonProperty("kss:publicIdentityPreKey") val publicIdentityPreKey: String,
    @JsonProperty("kss:publicSignedPrekey") val publicSignedPrekey: String,
    @JsonProperty("kss:publicOneTimePrekeys") val publicOneTimePrekeys: List<String>,
    @JsonProperty("kss:preKeySignature") val preKeySignature: String
) {
    fun convertToX25519(): X3DHPublicPreKeys {
        return X3DHPublicPreKeys(
            publicIdentityPreKey = X25519PublicKeyParameters(Base64.getDecoder().decode(publicIdentityPreKey)),
            publicSignedPrekey = X25519PublicKeyParameters(Base64.getDecoder().decode(publicSignedPrekey)),
            publicOneTimePrekeys = publicOneTimePrekeys.map { X25519PublicKeyParameters(Base64.getDecoder().decode(it)) },
            preKeySignature = Base64.getDecoder().decode(preKeySignature)
        )
    }
}

fun uploadPreKeys(podId: String, preKeys: X3DHPublicPreKeys) {
    val client = OkHttpClient()

    val jsonLd = """
        {
            "@context": {
                "kss": "https://kvasir.discover.ilabt.imec.be/vocab#"
            },
            "kss:publicIdentityPreKey": "${Base64.getEncoder().encodeToString(preKeys.publicIdentityPreKey.encoded)}",
            "kss:publicSignedPrekey": "${Base64.getEncoder().encodeToString(preKeys.publicSignedPrekey.encoded)}",
            "kss:publicOneTimePrekeys": [${preKeys.publicOneTimePrekeys.joinToString(", ") { "\"${Base64.getEncoder().encodeToString(it.encoded)}\"" }}],
            "kss:preKeySignature": "${Base64.getEncoder().encodeToString(preKeys.preKeySignature)}"
        }
    """.trimIndent()

    val b = Base64.getEncoder().encodeToString(preKeys.preKeySignature)
    val a = Base64.getDecoder().decode(Base64.getEncoder().encodeToString(preKeys.preKeySignature))

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
    val client = OkHttpClient()

    val requestGet = Request.Builder()
        .url("http://localhost:8080/bob/x3dh")
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

fun sendInitialMessage(podId:String, privateKeyToCheat: X25519PrivateKeyParameters, preKeys: X3DHPreKeys) {
    val targetPrekeys: X3DHPublicPreKeys = getPublicX3DHKeys(podId)

    val verified = xeddsa_verify(targetPrekeys.publicIdentityPreKey, privateKeyToCheat, targetPrekeys.publicSignedPrekey.encoded, targetPrekeys.preKeySignature)

    println(verified)

    if (!verified) {
        throw RuntimeException("Signature Verification failed")
    }

    val DH1 = DiffieHellman(preKeys.privateIdentityPreKey, targetPrekeys.publicSignedPrekey)

    val a = 2
}

fun processInitialMessage() {

}