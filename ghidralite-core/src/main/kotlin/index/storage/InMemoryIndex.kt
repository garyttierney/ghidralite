package io.github.garyttierney.ghidralite.core.index.storage

import io.github.garyttierney.ghidralite.core.index.Index
import io.github.garyttierney.ghidralite.core.index.loader.IndexBulkLoader
import java.util.concurrent.ConcurrentNavigableMap
import java.util.concurrent.ConcurrentSkipListMap

class InMemoryIndex<K : Any, V>(
    private val backingMap: ConcurrentSkipListMap<K, V> = ConcurrentSkipListMap()
) : Index<K, V>, ConcurrentNavigableMap<K, V> by backingMap {

    override suspend fun load(loader: IndexBulkLoader<K, V>) {
        loader.load()
            .collect {
                this[it.first] = it.second
            }
    }
}