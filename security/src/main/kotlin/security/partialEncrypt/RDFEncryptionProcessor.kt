package security.partialEncrypt

import security.crypto.aesGcmEncrypt
import java.security.MessageDigest
import java.util.*

object RDFEncryptionProcessor {

    private fun sha256Hash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(input.toByteArray())
        return Base64.getEncoder().encodeToString(hashBytes) // Encode as Base64 for readability
    }

    private fun getType(item: Any): String {
        val baseString = "http://www.w3.org/2001/XMLSchema#"
        when (item) {
            is String -> {
                return baseString + "string"
            }
            is Int -> {
                return baseString + "integer"
            }
        }
        return "Unsupported type used for $item"
    }


    fun encrypt(jsonMap: Map<String, Any>, secretKey: ByteArray, associatedData: ByteArray, predicatesToEncrypt: List<String>): Map<String, Any> {
        val encryptedMap = mutableMapOf<String, Any>()

        for (key in jsonMap.keys) {
            if (key.equals("@value")) return jsonMap


            if (predicatesToEncrypt.contains(key)) {
                // Predicate should be encrypted
                val value = jsonMap[key]
                val encryptedKey = aesGcmEncrypt(key.toByteArray(), secretKey, associatedData)
                val predicateHash = sha256Hash(key)

                when (value) {
                    is String -> {
                        // Value is a normal value
                        val encryptedValue = aesGcmEncrypt(value.toByteArray(), secretKey, associatedData)
                        val type = getType(value)
                        val ECMap = mapOf(
                            "EncryptionContainer" to EncryptionContainer(
                                `@value` = Base64.getEncoder().encodeToString(encryptedValue),
                                renc_datatype = type,
                                renc_hash = sha256Hash(value)
                            ),
                            "predicateHash" to predicateHash
                        )
                        encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), ECMap)
                    }

                    is List<*> -> {
                        if (value.size == 1) {
                            // Value shouldn't be a list
                            var firstValue = value.first()
                            when (firstValue) {
                                is Map<*, *> -> {
                                    if (firstValue.containsKey("@value")) {
                                        // The item is a normal value
                                        firstValue = (value.first() as Map<String, Any>)["@value"]
                                    }
                                    else {
                                        // The item is a nested JsonObject
                                        val nestedMap = mapOf(
                                            "@value" to encrypt(firstValue as Map<String, Any>, secretKey, associatedData, predicatesToEncrypt),
                                            "predicateHash" to predicateHash
                                        )
                                        encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), nestedMap)
                                        continue
                                    }
                                }
                            }

                            val encryptedValue = aesGcmEncrypt(firstValue.toString().toByteArray(), secretKey, associatedData)
                            val type = getType(firstValue!!)


                            val ECMap = mapOf(
                                "EncryptionContainer" to EncryptionContainer(
                                    `@value` = Base64.getEncoder().encodeToString(encryptedValue),
                                    renc_datatype = type,
                                    renc_hash = sha256Hash(firstValue.toString())
                                ),
                                "predicateHash" to predicateHash
                            )

                            encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), ECMap)
                        } else {
                            // Value is a real list
                            val list = mutableListOf<Map<String, Any>>()

                            for (listItem in value) {
                                when (listItem) {
                                    // Item in the list is a nested JsonObject
                                    is Map<*, *> -> {
                                        val nestedMap = encrypt(
                                            listItem as Map<String, Any>,
                                            secretKey,
                                            associatedData,
                                            predicatesToEncrypt
                                        )
                                        list.add(
                                            mapOf(
                                                "@value" to nestedMap
                                            )
                                        )
                                    }
                                    // Item in the list is a normal value
                                    else -> {
                                        val itemString = listItem.toString()
                                        val encryptedValue =
                                            aesGcmEncrypt(itemString.toByteArray(), secretKey, associatedData)
                                        val type = getType(itemString)

                                        val ECMap = mapOf(
                                            "EncryptionContainer" to EncryptionContainer(
                                                `@value` = Base64.getEncoder().encodeToString(encryptedValue),
                                                renc_datatype = type,
                                                renc_hash = sha256Hash(listItem.toString())
                                            )
                                        )
                                        list.add(ECMap)
                                    }
                                }
                            }
                            // add the encrypted list together with the predicate hash
                            val encryptedList = mapOf<String, Any>(
                                "@value" to list,
                                "predicateHash" to predicateHash
                            )
                            encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), encryptedList)
                        }
                    }
                }
            } else {
                // Predicate shouldn't be encrypted
                val value = jsonMap[key]

                when (value) {
                    is String -> {
                        // Value is a normal value
                        val valueMap = mapOf(
                            "@value" to value
                        )
                        encryptedMap.put(key, valueMap)
                    }
                    is List<*> -> {
                        if (value.size == 1) {
                            // Value shouldn't be a list
                            var firstValue = value.first()
                            when (firstValue) {
                                is Map<*, *> -> {
                                    if (firstValue.containsKey("@value")) {
                                        // The item is a normal value
                                        firstValue = (value.first() as Map<String, Any>)["@value"]
                                    }
                                    else {
                                        // The item is a nested JsonObject
                                        val nestedMap = mapOf(
                                            "@value" to encrypt(firstValue as Map<String, Any>, secretKey, associatedData, predicatesToEncrypt),
                                        )
                                        encryptedMap.put(key, nestedMap)
                                        continue
                                    }
                                }
                            }
                            val valueMap = mapOf(
                                "@value" to firstValue
                            )

                            encryptedMap.put(key, valueMap)
                        } else {
                            // Value is a real list
                            val list = mutableListOf<Map<String, Any>>()

                            for (listItem in value) {
                                when (listItem) {
                                    // Item in the list is a nested JsonObject
                                    is Map<*, *> -> {
                                        val nestedMap = encrypt(
                                            listItem as Map<String, Any>,
                                            secretKey,
                                            associatedData,
                                            predicatesToEncrypt
                                        )
                                        list.add(
                                            mapOf(
                                                "@value" to nestedMap
                                            )
                                        )
                                    }
                                    // Item in the list is a normal value
                                    else -> {
                                        val valueMap = mapOf(
                                            "@value" to listItem!!
                                        )
                                        list.add(valueMap)
                                    }
                                }
                            }
                            // add the encrypted list together with the predicate hash
                            val valueList = mapOf<String, Any>(
                                "@value" to list,
                            )
                            encryptedMap.put(key, valueList)
                        }
                    }
                }
            }
        }
        return encryptedMap
    }
}