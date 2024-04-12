package io.github.garyttierney.ghidralite.framework.search.index.program

import io.github.garyttierney.ghidralite.framework.db.GhidraRecord
import io.github.garyttierney.ghidralite.framework.db.GhidraTable
import io.github.garyttierney.ghidralite.framework.search.index.IndexBulkLoader
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.stream.consumeAsFlow
import java.util.stream.Stream

class ProgramDbTableLoader<T : GhidraRecord>(private val table: GhidraTable<T>, private val predicate: (T) -> Boolean = { true }) : IndexBulkLoader<T> {
    override suspend fun load(): Flow<T> = table.allAfter().asFlow()
}