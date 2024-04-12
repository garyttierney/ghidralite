package io.github.garyttierney.ghidralite.framework.search.index

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.reflect.KClass

/**
 * Maintains in-memory caches of frequently queried data.
 */
class Indexes {
    private val indexes = mutableMapOf<KClass<*>, ConcurrentLinkedQueue<*>>()

    @Suppress("UNCHECKED_CAST")
    private fun <T : Any> indexData(ty: KClass<T>) = indexes.computeIfAbsent(ty) {
        ConcurrentLinkedQueue<T>()
    } as ConcurrentLinkedQueue<T>

    fun <T : Any> write(ty: KClass<T>, values: Collection<T>) {
        indexData(ty).addAll(values)
    }

    fun <T : Any> query(ty: KClass<T>): Flow<T> = indexData(ty).asFlow()

    inline fun <reified T : Any> query(): Flow<T> = query(T::class)

    suspend fun <T : Any> load(ty: KClass<T>, bulkLoader: IndexBulkLoader<T>) {
        val items = mutableListOf<T>()
        bulkLoader.load().flowOn(Dispatchers.IO).toCollection(items)

        indexes[ty] = ConcurrentLinkedQueue(items)
    }

    suspend inline fun <reified T : Any> load(bulkLoader: IndexBulkLoader<T>) {
        load(T::class, bulkLoader)
    }

}