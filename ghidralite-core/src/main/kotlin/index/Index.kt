package io.github.garyttierney.ghidralite.core.index

import io.github.garyttierney.ghidralite.core.index.loader.IndexBulkLoader
import java.util.concurrent.ConcurrentNavigableMap
import java.util.stream.StreamSupport

interface Index<K, V> : ConcurrentNavigableMap<K, V> {
    suspend fun load(loader: IndexBulkLoader<K, V>)

    fun process(processor: (Map.Entry<K, V>) -> Unit) {
        StreamSupport.stream(entries.spliterator(), true).forEach(processor)
    }
}
