package security

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters

fun main() {
    /*


        START X3DH


     */


    // Bob want to enable Alice to get access to its pod
    // So they can exchange messages via this pod

    /*
        Step 0: Generate Prekeys
     */

    val Alice = User("alice")
    val Bob = User("bob")
    Alice.preKeys = generatePrekeys()
    Bob.preKeys = generatePrekeys()

    /*
        STEP 1: Place Keys on Server
        (From Bob)
     */

     uploadPreKeys(Bob.podId, Bob.preKeys!!.getPublic())

    /*
        STEP 2: Send the Initial Message
        (From Alice)
     */

    Alice.sharedKey = sendInitialMessage(Alice, Bob.podId, Bob.preKeys!!.privateIdentityPreKey, Alice.preKeys!!)

    /*
        STEP 3: Process the Initial Message
        (From Bob)
     */

    Bob.sharedKey = processInitialMessage(Bob, Bob.podId, Bob.preKeys!!)

    val a = 2


    /*


        X3DH FINISHED


     */

}