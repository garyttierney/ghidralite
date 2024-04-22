package io.github.garyttierney.ghidralite.core.search.index.program.symbol

import ghidra.program.model.symbol.SymbolType
import io.github.garyttierney.ghidralite.core.db.SymbolDbTable
import io.github.garyttierney.ghidralite.core.db.SymbolLookupDetails
import io.github.garyttierney.ghidralite.core.db.SymbolRecord
import io.github.garyttierney.ghidralite.core.index.loader.IndexBulkLoader
import it.unimi.dsi.fastutil.longs.Long2ObjectArrayMap
import it.unimi.dsi.fastutil.longs.Long2ObjectFunction
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filterNot
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.stream.consumeAsFlow

fun SymbolRecord.recordToLookup(
    table: SymbolDbTable,
    namespaceCache: Long2ObjectArrayMap<SymbolLookupDetails> = Long2ObjectArrayMap()
): SymbolLookupDetails {
    val cacheLoader = Long2ObjectFunction { key -> table.get(key).recordToLookup(table, namespaceCache) }
    return SymbolLookupDetails(
        key,
        type,
        name,
        if (parentId == 0L) null else namespaceCache.computeIfAbsent(parentId, cacheLoader)
    )
}

class SymbolIndexLoader(private val table: SymbolDbTable) : IndexBulkLoader<Long, SymbolLookupDetails> {
    override suspend fun load(): Flow<Pair<Long, SymbolLookupDetails>> {
        val namespaceCache = Long2ObjectArrayMap<SymbolLookupDetails>()

        return table.all()
            .consumeAsFlow()
            .filterNot {
                it.type == SymbolType.NAMESPACE || it.type == SymbolType.CLASS || it.type == SymbolType.LOCAL_VAR
                        || it.name.isBlank() || it.name.startsWith("Unwind") || it.name.startsWith("Catch")
            }
            .map {
                it.key to it.recordToLookup(table, namespaceCache)
            }
    }
}