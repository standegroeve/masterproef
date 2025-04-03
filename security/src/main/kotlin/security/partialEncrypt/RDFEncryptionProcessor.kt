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

        if (jsonMap.keys.size == 1 && jsonMap.containsKey("@value") && jsonMap["@value"] is String)
            return jsonMap


        for (key in jsonMap.keys) {

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
                                    // Item in the list is a nested JsonObject or a string inside a map
                                    is Map<*, *> -> {
                                        var newListItem: Any? = null
                                        if (listItem["@value"] is String) {
                                            // Item in the list is a string inside a map
                                            newListItem = listItem["@value"]
                                        }
                                        else {
                                            newListItem = encrypt(
                                                listItem as Map<String, Any>,
                                                secretKey,
                                                associatedData,
                                                predicatesToEncrypt
                                            )
                                        }
                                        list.add(
                                            mapOf(
                                                "@value" to newListItem!!
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

    private fun makeBlankNodeReference(currentChar: Char, encryptionContainer: EncryptionContainer): Map<String, Any> {
        return mapOf(
                "renc:encNLabel" to encryptionContainer.toString()
            )
    }

    private fun makeReificationQuad(currentReificationNumber: Int, subject: String, encryptedPredicate: String, predicateHash: String, objectValue: Any): Map<String, Any> {
        val predicateEC = EncryptionContainer(
            `@value` = encryptedPredicate,
            renc_datatype = "http://www.w3.org/2001/XMLSchema#string",
            renc_hash = predicateHash
        )

        return mapOf(
            "@id" to "ex:reificationQuad$currentReificationNumber",
            "rdf:type" to "rdf:Statement",
            "rdf:subject" to subject,
            "rdf:predicate" to "renc:encPredicate",
            "rdf:object" to objectValue,
            "renc:encPLabel" to predicateEC.toString()
        )
    }


    fun objectTransform(jsonMap: Map<String, Any>, currentChar: Char = 'A', currentReificationNumber: Int = 1,  references: Map<String, Any> = emptyMap()): Map<String, Any> {
        val transformedMap = mutableMapOf<String, Any>()
        var nextChar = currentChar
        var nextReificationNumber = currentReificationNumber
        var updatedReferences = references.toMutableMap()

        if (jsonMap.keys.size == 1 && jsonMap.containsKey("@value") && jsonMap["@value"] is String)
            return mapOf(
                "transformedMap" to jsonMap,
                "nextChar" to nextChar,
                "nextReificationNumber" to nextReificationNumber,
                "updatedReferences" to updatedReferences
            )

        val subject = (jsonMap["@id"] as Map<String, Any>)["@value"] as String

        if (references.containsKey(subject)) {
            // Handle subject transformation



            return mapOf(
                "transformedMap" to transformedMap,
                "nextChar" to nextChar,
                "nextReificationNumber" to nextReificationNumber,
                "updatedReferences" to updatedReferences
            )
        }

        for (key in jsonMap.keys) {


            val value = jsonMap[key] as Map<String, Any>


            if (value.containsKey("EncryptionContainer")) {
                // Object is encrypted and maybe also the predicate

                // Handle object transform
                val EC = value["EncryptionContainer"] as EncryptionContainer

                var blankNodeReference: Any? = null

                // Check if blankNode was already previously made
                if (references.containsKey(EC.renc_hash)) {
                    blankNodeReference = (references[EC.renc_hash] as Map<String, Any>).values.first()
                }
                else {
                    blankNodeReference = makeBlankNodeReference(nextChar, EC)
                }

                transformedMap.put("_:$nextChar", blankNodeReference!!)
                val newObjectValue = mapOf("@id" to "_:$nextChar")
                updatedReferences.put(EC.renc_hash, mapOf("_:$nextChar" to blankNodeReference))
                nextChar++

                // Check if predicate is encrypted
                if (value.containsKey("predicateHash")) {
                    // Predicate is encrypted

                    // Handle predicate transform
                    val predicateHash = value["predicateHash"] as String
                    var reificationQuad: Any? = null

                    // Check if reificationQuad was already previously made
                    if (references.containsKey(predicateHash)) {
                        val originalReificationQuad = (references[predicateHash] as Map<String, Any>).values.first() as Map<String, Any>
                        reificationQuad = originalReificationQuad.toMutableMap() // Creates copy of the reificationQuad
                        reificationQuad.put("rdf:object", newObjectValue)
                    }
                    else {
                        reificationQuad = makeReificationQuad(nextReificationNumber, subject, key, predicateHash, newObjectValue)
                    }

                    transformedMap.put("renc:encPredicate$nextReificationNumber", "ex:reificationQuad$nextReificationNumber")
                    transformedMap.put("ex:reificationQuad$nextReificationNumber", reificationQuad)
                    updatedReferences.put(predicateHash, mapOf("ex:reificationQuad$nextReificationNumber" to reificationQuad))
                    nextReificationNumber++
                }
                else {
                    // Predicate is not encrypted
                    transformedMap.put(key, newObjectValue)
                }
            }
            else {
                val valueObject = value["@value"]
                if (value.containsKey("predicateHash")) {
                    val predicateHash = value["predicateHash"] as String
                    // The predicate is encrypted (and maybe the object is encrypted and inside a list)
                    when(valueObject) {
                        is String -> {
                            // The valueObject is a string
                            val reificationQuad = makeReificationQuad(nextReificationNumber, subject, key, predicateHash, valueObject)
                            transformedMap.put("renc:encPredicate$nextReificationNumber", "ex:reificationQuad$nextReificationNumber")
                            transformedMap.put("ex:reificationQuad$nextReificationNumber", reificationQuad)
                            updatedReferences.put(predicateHash, mapOf("ex:reificationQuad$nextReificationNumber" to reificationQuad))
                            nextReificationNumber++
                        }
                        is Map<*, *> -> {
                            // The valueObject is a nested Json so a Map<String, Any>, recursion is needed
                            val recursionMap = objectTransform(valueObject as Map<String, Any>, nextChar, nextReificationNumber, updatedReferences)
                            val nestedMap = recursionMap["transformedMap"] as MutableMap<String, Any>
                            val updatedChar = recursionMap["nextChar"] as Char
                            val updatedReificationNumber = recursionMap["nextReificationNumber"] as Int
                            updatedReferences = recursionMap["updatedReferences"] as MutableMap<String, Any>

                            // Handle created blankNodeReferences in recursion
                            for (i in updatedChar - nextChar downTo 1) {
                                transformedMap.put("_:$nextChar", nestedMap["_:$nextChar"]!!)
                                nestedMap.remove("_:$nextChar")
                                nextChar++
                            }
                            // Handle created reificationQuads in recursion
                            for (i in updatedReificationNumber - nextReificationNumber downTo 1) {
                                transformedMap.put("ex:reificationQuad$nextReificationNumber", nestedMap["ex:reificationQuad$nextReificationNumber"]!!)
                                nestedMap.remove("ex:reificationQuad$nextReificationNumber")
                                nextReificationNumber++
                            }

                            val reificationQuad = makeReificationQuad(nextReificationNumber, subject, key, predicateHash, nestedMap)
                            transformedMap.put("renc:encPredicate$nextReificationNumber", "ex:reificationQuad$nextReificationNumber")
                            transformedMap.put("ex:reificationQuad$nextReificationNumber", reificationQuad)
                            updatedReferences.put(predicateHash, mapOf("ex:reificationQuad$nextReificationNumber" to reificationQuad))
                            nextReificationNumber++

                            transformedMap.put(key, reificationQuad)
                        }
                        is List<*> -> {
                            // The valueObject is a List containing a Map<String, Any>
                            val firstValue = (valueObject[0] as Map<String, Any>)["@value"]
                            when (firstValue) {
                                is String -> {
                                    // The list contains unencrypted strings
                                    val reificationQuad = makeReificationQuad(nextReificationNumber, subject, key, predicateHash, valueObject)
                                    transformedMap.put("renc:encPredicate$nextReificationNumber", "ex:reificationQuad$nextReificationNumber")
                                    transformedMap.put("ex:reificationQuad$nextReificationNumber", reificationQuad)
                                    updatedReferences.put(predicateHash, mapOf("ex:reificationQuad$nextReificationNumber" to reificationQuad))
                                    nextReificationNumber++
                                }
                                is EncryptionContainer -> {
                                    // The list contains encrypted Objects

                                    val transformedList = mutableListOf<Map<String, Any>>()

                                    for (item in valueObject) {
                                        val EC = (item as Map<String, Any>)["@value"] as EncryptionContainer

                                        var blankNodeReference: Any? = null

                                        // Check if blankNode was already previously made
                                        if (references.containsKey(EC.renc_hash)) {
                                            blankNodeReference = (references[EC.renc_hash] as Map<String, Any>).values.first()
                                        }
                                        else {
                                            blankNodeReference = makeBlankNodeReference(nextChar, EC)
                                        }

                                        transformedMap.put("_:$nextChar", blankNodeReference!!)
                                        val newObjectValue = mapOf("@id" to "_:$nextChar")
                                        updatedReferences.put(EC.renc_hash, mapOf("_:$nextChar" to blankNodeReference))
                                        nextChar++

                                        transformedList.add(
                                            mapOf("@value" to mapOf("@id" to newObjectValue))
                                        )
                                    }

                                    val reificationQuad = makeReificationQuad(nextReificationNumber, subject, key, predicateHash, transformedList)
                                    transformedMap.put("renc:encPredicate$nextReificationNumber", "ex:reificationQuad$nextReificationNumber")
                                    transformedMap.put("ex:reificationQuad$nextReificationNumber", reificationQuad)
                                    updatedReferences.put(predicateHash, mapOf("ex:reificationQuad$nextReificationNumber" to reificationQuad))
                                    nextReificationNumber++
                                }
                                is Map<*, *> -> {
                                    // The list contains nested JsonMaps so recursion is needed

                                    val transformedList = mutableListOf<Map<String, Any>>()

                                    for (item in valueObject) {
                                        val itemValue = (item as Map<String, Any>)["@value"] as Map<String, Any>
                                        val recursionMap = objectTransform(itemValue, nextChar, nextReificationNumber, updatedReferences)
                                        val nestedMap = recursionMap["transformedMap"] as MutableMap<String, Any>
                                        val updatedChar = recursionMap["nextChar"] as Char
                                        val updatedReificationNumber = recursionMap["nextReificationNumber"] as Int
                                        updatedReferences = recursionMap["updatedReferences"] as MutableMap<String, Any>

                                        // Handle created blankNodeReferences in recursion
                                        for (i in updatedChar - nextChar downTo 1) {
                                            transformedMap.put("_:$nextChar", nestedMap["_:$nextChar"]!!)
                                            nestedMap.remove("_:$nextChar")
                                            nextChar++
                                        }
                                        // Handle created reificationQuads in recursion
                                        for (i in updatedReificationNumber - nextReificationNumber downTo 1) {
                                            transformedMap.put("ex:reificationQuad$nextReificationNumber", nestedMap["ex:reificationQuad$nextReificationNumber"]!!)
                                            nestedMap.remove("ex:reificationQuad$nextReificationNumber")
                                            nextReificationNumber++
                                        }

                                        transformedList.add(mapOf("@value" to nestedMap))
                                    }

                                    val reificationQuad = makeReificationQuad(nextReificationNumber, subject, key, predicateHash, transformedList)
                                    transformedMap.put("renc:encPredicate$nextReificationNumber", "ex:reificationQuad$nextReificationNumber")
                                    transformedMap.put("ex:reificationQuad$nextReificationNumber", reificationQuad)
                                    updatedReferences.put(predicateHash, mapOf("ex:reificationQuad$nextReificationNumber" to reificationQuad))
                                    nextReificationNumber++
                                }
                            }
                        }
                    }
                }
                else {
                    // Nothing is encrypted
                    when (valueObject) {
                        is String -> {
                            // The valueObject is a String
                            transformedMap.put(key, value)
                        }
                        is Map<*, *> -> {
                            // The valueObject is a nested Json so a Map<String, Any>, recursion is needed
                            val recursionMap = objectTransform(valueObject as Map<String, Any>, nextChar, nextReificationNumber, updatedReferences)
                            val nestedMap = recursionMap["transformedMap"] as MutableMap<String, Any>
                            val updatedChar = recursionMap["nextChar"] as Char
                            val updatedReificationNumber = recursionMap["nextReificationNumber"] as Int
                            updatedReferences = recursionMap["updatedReferences"] as MutableMap<String, Any>

                            // Handle created blankNodeReferences in recursion
                            for (i in updatedChar - nextChar downTo 1) {
                                transformedMap.put("_:$nextChar", nestedMap["_:$nextChar"]!!)
                                nestedMap.remove("_:$nextChar")
                                nextChar++
                            }
                            // Handle created reificationQuads in recursion
                            for (i in updatedReificationNumber - nextReificationNumber downTo 1) {
                                transformedMap.put("ex:reificationQuad$nextReificationNumber", nestedMap["ex:reificationQuad$nextReificationNumber"]!!)
                                nestedMap.remove("ex:reificationQuad$nextReificationNumber")
                                nextReificationNumber++
                            }

                            transformedMap.put(key, nestedMap)
                        }
                        is List<*> -> {
                            // The valueObject is a List containing a Map<String, Any>
                            val firstValue = (valueObject[0] as Map<String, Any>)["@value"]
                            when (firstValue) {
                                is String -> {
                                    // The list contains unencrypted strings
                                    transformedMap.put(key, value)
                                }
                                is EncryptionContainer -> {
                                    // The list contains encrypted Objects
                                    val transformedList = mutableListOf<Map<String, Any>>()

                                    for (item in valueObject) {
                                        val EC = (item as Map<String, Any>)["@value"] as EncryptionContainer

                                        var blankNodeReference: Any? = null

                                        // Check if blankNode was already previously made
                                        if (references.containsKey(EC.renc_hash)) {
                                            blankNodeReference = transformedMap[references[EC.renc_hash]]
                                        }
                                        else {
                                            blankNodeReference = makeBlankNodeReference(nextChar, EC)
                                        }

                                        transformedMap.put("_:$nextChar", blankNodeReference!!)
                                        val newObjectValue = mapOf("@id" to "_:$nextChar")
                                        updatedReferences.put(EC.renc_hash, "_:$nextChar")
                                        nextChar++

                                        transformedList.add(
                                            mapOf("@value" to mapOf("@id" to newObjectValue))
                                        )
                                    }

                                    transformedMap.put(key, transformedList)
                                }
                                is Map<*, *> -> {
                                    // The list contains nested JsonMaps so recursion is needed
                                    val transformedList = mutableListOf<Map<String, Any>>()

                                    for (item in valueObject) {
                                        val itemValue = (item as Map<String, Any>)["@value"] as Map<String, Any>
                                        val recursionMap = objectTransform(itemValue, nextChar, nextReificationNumber, updatedReferences)
                                        val nestedMap = recursionMap["transformedMap"] as MutableMap<String, Any>
                                        val updatedChar = recursionMap["nextChar"] as Char
                                        val updatedReificationNumber = recursionMap["nextReificationNumber"] as Int
                                        updatedReferences = recursionMap["updatedReferences"] as MutableMap<String, Any>

                                        // Handle created blankNodeReferences in recursion
                                        for (i in updatedChar - nextChar downTo 1) {
                                            transformedMap.put("_:$nextChar", nestedMap["_:$nextChar"]!!)
                                            nestedMap.remove("_:$nextChar")
                                            nextChar++
                                        }
                                        // Handle created reificationQuads in recursion
                                        for (i in updatedReificationNumber - nextReificationNumber downTo 1) {
                                            transformedMap.put("ex:reificationQuad$nextReificationNumber", nestedMap["ex:reificationQuad$nextReificationNumber"]!!)
                                            nestedMap.remove("ex:reificationQuad$nextReificationNumber")
                                            nextReificationNumber++
                                        }

                                        transformedList.add(mapOf("@value" to nestedMap))
                                    }

                                    transformedMap.put(key, transformedList)
                                }
                            }
                        }
                    }
                }
            }
        }

        return mapOf(
            "transformedMap" to transformedMap,
            "nextChar" to nextChar,
            "nextReificationNumber" to nextReificationNumber,
            "updatedReferences" to updatedReferences
        )
    }
}