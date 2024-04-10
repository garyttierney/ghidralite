package io.github.garyttierney.ghidralite.framework.db

import GhidraField
import GhidraSchema
import GhidraType
import db.DBRecord
import db.Table


@GhidraSchema(
    version = 3,
    fields = [
        GhidraField(name = "name", type = GhidraType.String)
    ]
)
interface SymbolRecord : GhidraRecord {
    var name: String
}

class SymbolDbTable(inner: Table) : GhidraTable<SymbolRecord>(inner) {
    override fun from(record: DBRecord) = SymbolRecordImpl(record)
}