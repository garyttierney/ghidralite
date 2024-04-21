package io.github.garyttierney.ghidralite.core.db

import GhidraField
import GhidraSchema
import GhidraType
import db.DBRecord
import db.Table
import ghidra.program.model.symbol.SymbolType
import io.github.garyttierney.ghidralite.core.LookupElement

data class SymbolLookupDetails(
    val id: Long,
    val type: SymbolType,
    override val label: String,
    override val parent: SymbolLookupDetails?
) : LookupElement {
    override val key: Any = id
    override val icon
        get() = when (type) {
            SymbolType.FUNCTION -> "/expui/nodes/function_dark.svg"
            SymbolType.NAMESPACE -> "/expui/nodes/package_dark.svg"
            SymbolType.GLOBAL_VAR -> "/expui/nodes/gvariable_dark.svg"
            SymbolType.LIBRARY -> "/expui/nodes/library_dark.svg"
            SymbolType.CLASS -> "/expui/nodes/class_dark.svg"
            else -> "/expui/nodes/static_dark.svg"
        }

    override val namespace: String
        get() {
            return ancestors().map { it.label }.toList().reversed().joinToString("::")
        }
}


@GhidraSchema(
    version = 3,
    fields = [
        GhidraField(name = "name", type = GhidraType.String),
        GhidraField(name = "address", type = GhidraType.Long),
        GhidraField(name = "parentId", type = GhidraType.Long),
        GhidraField(name = "typeOrdinal", type = GhidraType.Byte),
    ]
)
interface SymbolRecord : GhidraRecord {
    var name: String
    var address: Long
    var parentId: Long
    var typeOrdinal: Byte
    var type: SymbolType
        get() = SymbolType.getSymbolType(typeOrdinal.toInt())
        set(value) {
            typeOrdinal = value.id
        }

}

class SymbolDbTable(inner: Table) : GhidraTable<SymbolRecord>(inner) {
    override fun from(record: DBRecord) = SymbolRecordImpl(record)
}