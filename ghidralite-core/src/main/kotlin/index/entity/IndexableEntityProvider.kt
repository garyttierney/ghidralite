package io.github.garyttierney.ghidralite.core.index.entity

interface IndexableEntityProvider<K, T : IndexableEntity<K>, S : Any> {
    fun entityRemovals(changedEntity: S) : Sequence<T> = entityChanges(changedEntity)

    fun entityChanges(changedEntity: S) : Sequence<T>
}