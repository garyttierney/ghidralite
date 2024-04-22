package io.github.garyttierney.ghidralite.core.search.symbol

import ghidra.program.database.symbol.SymbolDB
import ghidra.program.model.symbol.Symbol
import ghidra.program.model.symbol.SymbolType
import io.github.garyttierney.ghidralite.core.db.SymbolLookupDetails
import io.github.garyttierney.ghidralite.core.index.entity.IndexableEntityProvider

fun Symbol.toLookupDetails(): SymbolLookupDetails = SymbolLookupDetails(
    id = id,
    type = symbolType,
    label = name,
    parent = parentNamespace?.symbol?.takeIf { it.name == "global" }?.toLookupDetails(),
)

val trivialSymbolTypes = setOf(SymbolType.CLASS, SymbolType.NAMESPACE, SymbolType.LOCAL_VAR)

fun Symbol.isTrivial() =
    trivialSymbolTypes.contains(symbolType) || name.startsWith("Unwind") || name.startsWith("Catch")


class SymbolProvider : IndexableEntityProvider<Long, SymbolLookupDetails, Symbol> {
    override fun entityChanges(changedEntity: Symbol) = sequence {
        if (!changedEntity.isTrivial()) {
            yield((changedEntity as SymbolDB).toLookupDetails())
        }
    }
}