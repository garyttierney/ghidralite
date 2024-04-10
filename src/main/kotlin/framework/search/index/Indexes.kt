package io.github.garyttierney.ghidralite.framework.search.index

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import java.util.concurrent.locks.ReadWriteLock
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.withLock
import kotlin.reflect.KClass

class IndexData(val values: ArrayDeque<Any>, val lock: ReadWriteLock = ReentrantReadWriteLock())

/**
 * Maintains in-memory caches of frequently queried data.
 */
class Indexes(private val coroutineScope: CoroutineScope) {
    private val indexes = mutableMapOf<KClass<*>, IndexData>()

    suspend fun <T : Any> registerAndLoad(ty: KClass<T>, changeSource: Flow<IndexChange<T>>, bulkLoader: IndexBulkLoader<T>) {
        val indexData = IndexData(ArrayDeque())
        indexes[ty] = indexData

        coroutineScope.launch {
            changeSource.collect { item ->
                val lock = indexData.lock.writeLock()
                lock.withLock {
                    indexData.values.add(item)
                }
            }
        }

        val loadingItems = bulkLoader.load()
        val lock = indexData.lock.writeLock()

        loadingItems.collect {
            lock.withLock {
                indexData.values.add(it)
            }
        }
    }

    suspend inline fun <reified T : Any> registerAndLoad(changeSource: Flow<IndexChange<T>>, bulkLoader: IndexBulkLoader<T>) {
        registerAndLoad(T::class, changeSource, bulkLoader)
    }

}