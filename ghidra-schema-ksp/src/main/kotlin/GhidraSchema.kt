import kotlin.reflect.KClass

enum class GhidraType {
    Byte,
    Int,
    Long,
    String,
}

annotation class GhidraField(val name: String, val type: GhidraType)

annotation class GhidraSchema(val version: Int, val fields: Array<GhidraField>)
