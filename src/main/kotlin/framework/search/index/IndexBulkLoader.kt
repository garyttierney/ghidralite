package io.github.garyttierney.ghidralite.framework.search.index

import kotlinx.coroutines.flow.Flow

interface IndexBulkLoader<T : Any> {
    suspend fun load(): Flow<T>
}