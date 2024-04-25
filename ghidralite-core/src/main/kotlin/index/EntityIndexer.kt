package io.github.garyttierney.ghidralite.core.index

import io.github.garyttierney.ghidralite.core.index.change.IndexChange
import io.github.garyttierney.ghidralite.core.index.change.IndexChangeFlowProvider
import io.github.garyttierney.ghidralite.core.index.entity.IndexableEntity
import io.github.garyttierney.ghidralite.core.index.entity.IndexableEntityProvider
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.produceIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.time.Duration.Companion.seconds

private const val BATCH_SIZE = 50

class EntityIndexer<K : Any, T : IndexableEntity<K>, S : Any>(
    private val index: Index<K, T>,
    private val entityProvider: IndexableEntityProvider<K, T, S>
) {
    suspend fun index(changeFlowProvider: IndexChangeFlowProvider<S>) = coroutineScope {
        val changeFlow = changeFlowProvider.getFlow()
        val channel = changeFlow.produceIn(this)

        while (isActive) {
            val batchTimeout = 2.seconds
            val removals = mutableSetOf<K>()
            val changes = mutableMapOf<K, T>()

            while (removals.size + changes.size < BATCH_SIZE) {
                val item = withTimeoutOrNull(batchTimeout) { channel.receive() }
                if (item == null) {
                    break
                }

                when (item) {
                    is IndexChange.Removed<S> -> {
                        removals += entityProvider.entityRemovals(item.value).map { it.key }
                    }

                    else -> {
                        entityProvider.entityChanges(item.value).forEach {
                            changes[it.key] = it
                        }
                    }
                }
            }

            index.putAll(changes)
            removals.forEach(index::remove)

            removals.clear()
            changes.clear()
        }

    }
}