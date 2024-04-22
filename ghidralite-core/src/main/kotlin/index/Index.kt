package io.github.garyttierney.ghidralite.core.index

import io.github.garyttierney.ghidralite.core.index.loader.IndexBulkLoader
import java.util.stream.StreamSupport

interface Index<K, V> {
    fun entries(): Iterable<Map.Entry<K, V>>

    suspend fun load(loader: IndexBulkLoader<K, V>)

    fun process(processor: (Map.Entry<K, V>) -> Unit) {
        StreamSupport.stream(entries().spliterator(), true).forEach(processor)
    }

    fun remove(key: K)
    fun write(elements: Iterable<Map.Entry<K, V>>) = write(elements.asSequence().map { it.key to it.value })
    fun write(elements: Sequence<Pair<K, V>>)
}