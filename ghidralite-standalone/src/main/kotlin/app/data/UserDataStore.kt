package io.github.garyttierney.ghidralite.standalone.app.data

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromJsonElement
import java.nio.file.Files
import java.nio.file.Paths

class UserDataStore {
    val finalizers = mutableListOf<() -> Unit>()

    fun resolvePath(name: String) = Paths.get("data", "$name.json")

    inline fun <reified T : Any> resolve(): UserData<T> {
        val name = T::class.qualifiedName ?: error("No metadata available for configuration class")
        val path = resolvePath(name)
        val data = if (Files.exists(path)) {
            Json.decodeFromJsonElement<T>(Json.parseToJsonElement(Files.readString(path, Charsets.UTF_8))) as T
        } else {
            val ctor = T::class.java.getConstructor()
            ctor.newInstance()
        }

        finalizers.add {
            Files.createDirectories(path.parent)
            Files.writeString(path, Json.encodeToString(data), Charsets.UTF_8)
        }

        return UserData(data)
    }

    fun flush() {
        finalizers.forEach { it() }
        finalizers.clear()
    }
}