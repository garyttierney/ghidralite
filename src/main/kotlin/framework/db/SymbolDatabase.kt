package io.github.garyttierney.ghidralite.framework.db

import GhidraField
import GhidraSchema
import GhidraType
import db.DBRecord
import db.Table
import ghidra.program.model.symbol.SymbolType


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
        set(value) { typeOrdinal = value.id }
}

class SymbolDbTable(inner: Table) : GhidraTable<SymbolRecord>(inner) {
    override fun from(record: DBRecord) = SymbolRecordImpl(record)
}