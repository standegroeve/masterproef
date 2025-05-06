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
import kvasir.definitions.security.MessageStorage

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
    @JsonProperty(KvasirVocab.messageStorage)
    val messageStorage: Map<String, List<Any>>? = null
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
    fun getMessages(hashedPodId: String): MessageStorage {
        if (messageStorage.isNullOrEmpty()) {


            throw NotFoundException("No new messages")
        }
        val rawMessages = messageStorage[hashedPodId]

        if (rawMessages.isNullOrEmpty()) {
            throw NotFoundException("No messages found for this conversation")
        }
        val mappedMessages = rawMessages.map {
            JsonObject(it as Map<String, Any>).mapTo(EncryptedMessage::class.java)
        }
        return MessageStorage(mappedMessages)
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