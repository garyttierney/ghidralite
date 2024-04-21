package io.github.garyttierney.ghidralite.core.search.index

import it.unimi.dsi.fastutil.objects.ObjectBigArrayBigList
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.toCollection
import java.util.stream.Stream
import kotlin.reflect.KClass

/**
 * Maintains in-memory caches of frequently queried data.
 */
class Indexes {
    private val indexes = mutableMapOf<KClass<*>, ObjectBigArrayBigList<*>>()

    @Suppress("UNCHECKED_CAST")
    private fun <T : Any> indexData(ty: KClass<T>) = indexes.computeIfAbsent(ty) {
        ObjectBigArrayBigList<T>()
    } as ObjectBigArrayBigList<T>

    fun <T : Any> write(ty: KClass<T>, values: Collection<T>) {
        indexData(ty).addAll(values)
    }

    fun <T : Any> stream(ty: KClass<T>): Stream<T> = indexData(ty).parallelStream()
    inline fun <reified T : Any> stream(): Stream<T> = stream(T::class)

    fun <T : Any> query(ty: KClass<T>): Flow<T> = indexData(ty).asFlow()
    inline fun <reified T : Any> query(): Flow<T> = query(T::class)

    suspend fun <T : Any> load(ty: KClass<T>, bulkLoader: IndexBulkLoader<T>) {
        val items = ObjectBigArrayBigList<T>()
        bulkLoader.load().flowOn(Dispatchers.IO).toCollection(items)

        indexes[ty] = ObjectBigArrayBigList(items)
    }

    suspend inline fun <reified T : Any> load(bulkLoader: IndexBulkLoader<T>) {
        load(T::class, bulkLoader)
    }

}