package io.github.garyttierney.ghidralite.core.index.change

import kotlinx.coroutines.flow.Flow

interface IndexChangeFlowProvider<T> {
    fun getFlow() : Flow<IndexChange<T>>
}