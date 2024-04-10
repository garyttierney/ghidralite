package io.github.garyttierney.ghidralite.framework.search.index.program

import io.github.garyttierney.ghidralite.framework.db.GhidraRecord
import io.github.garyttierney.ghidralite.framework.db.GhidraTable
import io.github.garyttierney.ghidralite.framework.search.index.IndexBulkLoader
import kotlinx.coroutines.flow.asFlow

class ProgramDbTableLoader<T : GhidraRecord>(private val table: GhidraTable<T>) : IndexBulkLoader<T> {
    override suspend fun load() = table.allAfter().asFlow()
}