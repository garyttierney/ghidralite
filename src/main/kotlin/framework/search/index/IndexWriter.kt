package io.github.garyttierney.ghidralite.framework.search.index

import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.produceIn
import kotlinx.coroutines.withTimeout
import kotlin.reflect.KClass
import kotlin.time.Duration.Companion.seconds

class IndexWriter<T : Any>(private val indexes: Indexes, private val type: KClass<T>) {
    @OptIn(DelicateCoroutinesApi::class)
    suspend fun run(changes: Flow<IndexChange<T>>) = coroutineScope {
        val channel = changes.produceIn(this)

        while (!channel.isClosedForReceive) {
            val batch = mutableListOf<T>()

            try {
                withTimeout(2.seconds) {
                    while (batch.size < 50) {
                        batch.add(channel.receive().value)
                    }
                }
            } catch (e: TimeoutCancellationException) {
                // Nothing to do, time to write the batch
            }

            // Batch filled, either via timeout or capacity reached
            indexes.write(type, batch)
        }
    }
}