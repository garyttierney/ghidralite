package io.github.garyttierney.ghidralite.core.search.index.program.symbol

import ghidra.program.model.symbol.Symbol
import ghidra.program.util.ChangeManager
import io.github.garyttierney.ghidralite.core.search.index.program.ProgramChangeSnapshotStrategy

object SymbolSnapshotStrategy : ProgramChangeSnapshotStrategy<Symbol> {
    override fun snapshot(event: Int, old: Any, new: Any): Symbol {
        return when (event) {
            ChangeManager.DOCR_SYMBOL_ADDED -> new as Symbol
            ChangeManager.DOCR_SYMBOL_RENAMED -> new as Symbol
            else -> throw Exception("Unreachable")
        }
    }
}