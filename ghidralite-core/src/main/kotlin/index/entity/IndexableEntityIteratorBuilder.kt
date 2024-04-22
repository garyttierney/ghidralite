package io.github.garyttierney.ghidralite.core.index.entity

class IndexableEntityIteratorBuilder<K> {
    private val keys = mutableListOf<K>()

    fun append(entity: IndexableEntity<K>) = keys.add(entity.key)
}