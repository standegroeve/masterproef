package security.benchmarks

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import security.User
import security.X3DH
import security.crypto.KeyUtils.generatePrekeys
import java.nio.ByteBuffer
import kotlin.system.measureNanoTime
import kotlin.system.measureTimeMillis

fun benchmarkX3DH(tripleCount: Int, accounts: Int): MutableList<Long> {
    val alice = User("alice")

    val times = mutableListOf<Long>()

    val authCodes = listOf(
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        ""
    )
    /*
        Initialize both Alice and Bob
     */
    alice.preKeys = generatePrekeys()

    for (i in 1..accounts) {
        val bob = User("bob$i")
        val authCode = authCodes[i-1]

        bob.preKeys = generatePrekeys()

        val x3dhTime = measureNanoTime {
            X3DH.initiateSliceSchema(bob.username, authCode)
            X3DH.uploadPreKeys(bob.username, bob.preKeys!!.getPublic(), authCode)

            val maxRetries = 5
            var attempt = 0
            var currentDelay: Long = 200

            while (attempt < maxRetries) {
                try {
                    alice.sharedKey = X3DH.sendInitialMessage(alice, bob.username, alice.preKeys!!, authCode)
                    break
                }
                catch (e: RuntimeException) {
                    runBlocking {
                        delay(currentDelay)
                    }
                    currentDelay *= 2
                    attempt++
                    if (attempt == maxRetries) {
                        throw Error("Too much tries!!!!!")
                    }
                }
            }

            attempt = 0
            currentDelay = 200

            while (attempt < maxRetries) {
                try {
                    bob.sharedKey = X3DH.processInitialMessage(bob, bob.username, bob.preKeys!!, authCode)
                    break
                }
                catch (e: RuntimeException) {
                    runBlocking {
                        delay(currentDelay)
                    }
                    currentDelay *= 2
                    attempt++
                    if (attempt == maxRetries) {
                        throw Error("Too much tries!!!!!")
                    }
                }
            }
        }
        times.add(x3dhTime)
    }

    return times
}