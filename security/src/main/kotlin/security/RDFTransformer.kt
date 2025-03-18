package security

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import security.crypto.aesGcmEncrypt
import java.util.*

object RDFTransformer {

    fun encrypt(jsonMap: Map<String, Any>, secretKey: ByteArray, associatedData: ByteArray): Map<String, Any> {
        val encryptedMap = mutableMapOf<String, Any>()
        for (key in jsonMap.keys) {
            if (key.contains("@")) {
                encryptedMap.put(key, jsonMap[key]!!)
            }
            else {
                val encryptedKey = aesGcmEncrypt(key.toByteArray(), secretKey, associatedData)
                val value = jsonMap[key] as List<*>

                if (value.size == 1) {
                    val listItem = (value as  List<Map<String,Any>>)[0]
                    if (listItem.contains("@value")) {
                        val itemString = listItem["@value"] as String
                        val encryptedValue = aesGcmEncrypt(itemString.toByteArray(), secretKey, associatedData)
                        encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), Base64.getEncoder().encodeToString(encryptedValue))
                    }
                    else {
                        val nestedEncryptedMap = encrypt(listItem, secretKey, associatedData)
                        encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), nestedEncryptedMap)
                    }
                }
                else {
                    val listEncrypted = mutableListOf<Any>()
                    for (item in value) {
                        if (item is String) {
                            val encryptedValue = aesGcmEncrypt(item.toByteArray(), secretKey, associatedData)
                            listEncrypted.add(Base64.getEncoder().encodeToString(encryptedValue))
                        }
                        else {
                            val itemEncryptedMap = encrypt(item as Map<String, Any>, secretKey, associatedData)
                            listEncrypted.add(itemEncryptedMap)
                        }
                    }
                    encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), listEncrypted)
                }

//                val encryptedKey = aesGcmEncrypt(key.toByteArray(), secretKey, associatedData)
//                val value = (jsonMap[key] as List<Map<String, Any>>)[0]["@value"]
//                when (value) {
//                    is String -> {
//                        println("check")
//                        val encryptedValue = aesGcmEncrypt(value.toByteArray(), secretKey, associatedData)
//                        encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), Base64.getEncoder().encodeToString(encryptedValue))
//                    }
//                    is Map<*, *> -> {
//                        println("check")
//                        val nestedEncryptedMap = encrypt(value as Map<String, Any>, secretKey, associatedData)
//                        encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), nestedEncryptedMap)
//                    }
//                    is List<*> -> {
//                        val listEncrypted = mutableListOf<Any>()
//                        for (item in value) {
//                            if (item is String) {
//                                val encryptedValue = aesGcmEncrypt(item.toByteArray(), secretKey, associatedData)
//                                listEncrypted.add(Base64.getEncoder().encodeToString(encryptedValue))
//                            }
//                            else {
//                                val itemEncryptedMap = encrypt(item as Map<String, Any>, secretKey, associatedData)
//                                listEncrypted.add(itemEncryptedMap)
//                            }
//                        }
//                        encryptedMap.put(Base64.getEncoder().encodeToString(encryptedKey), listEncrypted)
//                    }
//                }
            }
        }
        return encryptedMap
    }

}