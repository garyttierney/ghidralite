package io.github.garyttierney.ghidralite.core.search.index.program.symbol

import ghidra.program.util.ChangeManager
import io.github.garyttierney.ghidralite.core.db.SymbolRecord
import io.github.garyttierney.ghidralite.core.search.index.program.ProgramChangeSnapshotStrategy

object SymbolSnapshotStrategy : ProgramChangeSnapshotStrategy<SymbolRecord> {
    override fun snapshot(event: Int, old: Any, new: Any): SymbolRecord {
        return when (event) {
            ChangeManager.DOCR_SYMBOL_ADDED -> new as SymbolRecord
            ChangeManager.DOCR_SYMBOL_RENAMED -> new as SymbolRecord
            else -> throw Exception("Unreachable")
        }
    }
}