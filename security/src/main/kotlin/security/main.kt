package security

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters

fun main() {
    // Bob want to enable Alice to get access to its pod
    // So they can exchange messages via this pod

    val podId = "bob"

    /*
        Step 0: Generate Prekeys
     */

    val AliceKeys: X3DHPreKeys = generatePrekeys()
    val BobKeys: X3DHPreKeys = generatePrekeys()


    /*
        STEP 1: Place Keys on Server
     */

     uploadPreKeys(podId, BobKeys.getPublic())

    /*
        STEP 2: Send the Initial Message
     */

    sendInitialMessage(podId, BobKeys.privateIdentityPreKey, AliceKeys)
}