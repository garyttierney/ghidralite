package io.github.garyttierney.ghidralite.core.search.index

import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.produceIn
import kotlinx.coroutines.withTimeoutOrNull
import java.time.Duration
import java.time.Instant
import kotlin.reflect.KClass
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration

const val BATCH_SIZE = 250;

class IndexWriter<T : Any>(private val indexes: Indexes, private val type: KClass<T>) {
    @OptIn(ExperimentalCoroutinesApi::class, DelicateCoroutinesApi::class)
    suspend fun run(changes: Flow<IndexChange<T>>) = coroutineScope {
        val channel = changes.produceIn(this)
        val lastWrite = Instant.now()

        while (!channel.isClosedForReceive) {
            val batch = mutableListOf<T>()

            val batchTimeout = 2.seconds.toJavaDuration()

            while (batch.size >= BATCH_SIZE || Duration.between(lastWrite, Instant.now()) > batchTimeout) {
                val item = withTimeoutOrNull(2.seconds) { channel.receive() }
                if (item != null) {
                    batch.add(item.value)
                }
            }

            indexes.write(type, batch)
        }
    }
}