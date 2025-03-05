package kvasir.definitions.kg

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import io.smallrye.mutiny.Uni
import io.vertx.core.json.Json
import io.vertx.core.json.JsonObject
import jakarta.ws.rs.NotFoundException
import kvasir.definitions.rdf.JsonLdKeywords
import kvasir.definitions.rdf.KvasirVocab
import kvasir.definitions.security.EncryptedMessage
import kvasir.definitions.security.InitialMessage
import kvasir.definitions.security.MessagesLists
import kvasir.definitions.security.PublicX3DHKeys

interface PodStore {

    fun persist(pod: Pod): Uni<Void>

    fun list(): Uni<List<Pod>>

    fun getById(id: String): Uni<Pod?>

    fun deleteById(id: String): Uni<Void>

}

/**
 * A PodAuthInitializer can be provided by a plugin to initialize the auth configuration for a new pod
 * with the default authorization server (to streamline the process of creating a new pod).
 */
interface PodAuthInitializer {

    fun initialize(podId: String, podName: String): Uni<AuthConfiguration>

}

data class Pod(
    @JsonProperty(JsonLdKeywords.id)
    val id: String,
    @JsonProperty(KvasirVocab.configuration)
    val configuration: Map<String, Any>,
    @JsonProperty(KvasirVocab.x3dhKeys)
    val x3dhKeys: Map<String, Any>? = null
) {

    @JsonIgnore
    fun getDefaultContext(): Map<String, Any> {
        return configuration[PodConfigurationProperty.DEFAULT_CONTEXT]?.let { JsonObject(it as String).map } ?: emptyMap()
    }

    @JsonIgnore
    fun getAutoIngestRDF(): Boolean {
        return configuration[PodConfigurationProperty.AUTO_INGEST_RDF] as? Boolean == true
    }

    @JsonIgnore
    fun getAuthConfiguration(): AuthConfiguration? {
        return configuration[KvasirVocab.authConfiguration]?.let {
                JsonObject(it as Map<String, Any>).mapTo(AuthConfiguration::class.java)
        }
    }

    @JsonIgnore
    fun getPreKeys(): PublicX3DHKeys? {
        val keys = x3dhKeys?.get(KvasirVocab.publicX3DHKeys)
            ?: throw NotFoundException("X3DH keys not found")
        return JsonObject(keys as Map<String, Any>).mapTo(PublicX3DHKeys::class.java)
    }

    @JsonIgnore
    fun getNewMessages(): MessagesLists {
        val inBoxMessages = x3dhKeys?.get(KvasirVocab.messageInbox) as? List<*>
        val outBoxMessages = x3dhKeys?.get(KvasirVocab.messageOutbox) as? List<*>
        if (inBoxMessages == null && outBoxMessages == null)
            throw NotFoundException("No new messages")
        return MessagesLists(
            (inBoxMessages ?: emptyList<EncryptedMessage>()).map {
                JsonObject(it as Map<String, Any>).mapTo(EncryptedMessage::class.java)
            },
            (outBoxMessages ?: emptyList<EncryptedMessage>()).map {
                JsonObject(it as Map<String, Any>).mapTo(EncryptedMessage::class.java)
            }
        )
    }

    @JsonIgnore
    fun getInitialMessage(): InitialMessage? {
        val message = x3dhKeys?.get(KvasirVocab.initialMessage)
            ?: throw NotFoundException("InitialMessage not found")
        return JsonObject(message as Map<String, Any>).mapTo(InitialMessage::class.java)
    }

}

object PodConfigurationProperty {

    const val DEFAULT_CONTEXT = KvasirVocab.defaultContext
    const val AUTO_INGEST_RDF = KvasirVocab.autoIngestRDF

}

data class AuthConfiguration(
    @JsonProperty(KvasirVocab.serverUrl)
    val serverUrl: String,
    @JsonProperty(KvasirVocab.clientId)
    val clientId: String,
    @JsonProperty(KvasirVocab.clientSecret)
    val clientSecret: String,
)

enum class PodEventType {
    CREATED,
    UPDATED,
    DELETED,
}

data class PodEvent(
    val type: PodEventType,
    val podId: String
)