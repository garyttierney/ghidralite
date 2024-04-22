package io.github.garyttierney.ghidralite.core.search.symbol

import ghidra.program.database.symbol.SymbolDB
import ghidra.program.model.symbol.Symbol
import io.github.garyttierney.ghidralite.core.db.SymbolLookupDetails
import io.github.garyttierney.ghidralite.core.index.entity.IndexableEntityProvider

fun Symbol.toLookupDetails(): SymbolLookupDetails = SymbolLookupDetails(
    id = id,
    type = symbolType,
    label = name,
    parent = parentNamespace?.symbol?.takeIf { it.name == "global" }?.toLookupDetails(),
)

class SymbolProvider() : IndexableEntityProvider<Long, SymbolLookupDetails, Symbol> {
    override fun entityChanges(changedEntity: Symbol) = sequence {
        yield((changedEntity as SymbolDB).toLookupDetails())
    }
}