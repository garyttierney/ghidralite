package io.github.garyttierney.ghidralite.core.search.index.program.symbol

import ghidra.program.model.symbol.SymbolType
import io.github.garyttierney.ghidralite.core.db.SymbolDbTable
import io.github.garyttierney.ghidralite.core.db.SymbolLookupDetails
import io.github.garyttierney.ghidralite.core.db.SymbolRecord
import io.github.garyttierney.ghidralite.core.search.index.IndexBulkLoader
import it.unimi.dsi.fastutil.longs.Long2ObjectArrayMap
import it.unimi.dsi.fastutil.longs.Long2ObjectFunction
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filterNot
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.stream.consumeAsFlow

class SymbolIndexLoader(private val table: SymbolDbTable) : IndexBulkLoader<SymbolLookupDetails> {
    override suspend fun load(): Flow<SymbolLookupDetails> {
        val namespaceCache = Long2ObjectArrayMap<SymbolLookupDetails>()

        fun recordToLookup(record: SymbolRecord): SymbolLookupDetails {
            val cacheLoader = Long2ObjectFunction { key -> recordToLookup(table.get(key)) }
            return SymbolLookupDetails(
                record.key,
                record.type,
                record.name,
                if (record.parentId == 0L) null else namespaceCache.computeIfAbsent(record.parentId, cacheLoader)
            )
        }

        return table.all().consumeAsFlow()
            .filterNot {
                it.type == SymbolType.NAMESPACE || it.type == SymbolType.CLASS || it.name.isBlank() || it.name.startsWith(
                    "Unwind"
                ) || it.name.startsWith(
                    "Catch"
                )
            }
            .map(::recordToLookup)
    }
}