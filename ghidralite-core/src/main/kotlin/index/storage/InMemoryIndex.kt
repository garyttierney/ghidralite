package io.github.garyttierney.ghidralite.core.index.storage

import io.github.garyttierney.ghidralite.core.index.Index
import io.github.garyttierney.ghidralite.core.index.loader.IndexBulkLoader
import java.util.concurrent.ConcurrentHashMap

class InMemoryIndex<K : Any, V> : Index<K, V> {
    private val entries = ConcurrentHashMap<K, V>()

    override fun entries(): Iterable<Map.Entry<K, V>> = entries.asIterable()

    override suspend fun load(loader: IndexBulkLoader<K, V>) {
        loader.load()
            .collect {
                entries[it.first] = it.second
            }
    }

    override fun remove(key: K) {
        entries.remove(key)
    }

    override fun write(elements: Sequence<Pair<K, V>>) = entries.putAll(elements)
}