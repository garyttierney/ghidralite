package io.github.garyttierney.ghidralite.core.index.entity

/**
 * An [IndexableEntityProvider] provides a sequence of [IndexableEntity]s for a given change operation and a source entity.
 */
interface IndexableEntityProvider<K, T : IndexableEntity<K>, S : Any> {
    fun entityRemovals(changedEntity: S): Sequence<T> = entityChanges(changedEntity)

    fun entityChanges(changedEntity: S): Sequence<T>
}