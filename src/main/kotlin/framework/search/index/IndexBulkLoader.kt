package io.github.garyttierney.ghidralite.framework.search.index

import kotlinx.coroutines.flow.Flow
import java.util.stream.Stream

interface IndexBulkLoader<T : Any> {
    suspend fun load(): Stream<T>
}