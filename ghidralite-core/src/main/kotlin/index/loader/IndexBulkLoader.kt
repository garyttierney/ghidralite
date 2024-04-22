package io.github.garyttierney.ghidralite.core.index.loader

import kotlinx.coroutines.flow.Flow

interface IndexBulkLoader<K, T> {
    suspend fun load(): Flow<Pair<K, T>>
}