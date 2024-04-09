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
interface Symbol : Record {
    var name: String
}

class SymbolDbTable(inner: Table) : GhidraTable<Symbol>(inner) {
    override fun from(record: DBRecord) = SymbolImpl(record)
}