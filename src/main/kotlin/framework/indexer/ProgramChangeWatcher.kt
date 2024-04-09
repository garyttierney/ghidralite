package io.github.garyttierney.ghidralite.framework.indexer

import ghidra.framework.model.DomainObjectChangedEvent
import ghidra.framework.model.DomainObjectListener
import ghidra.framework.model.EventType
import ghidra.program.model.listing.Program
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.Channel.Factory.BUFFERED
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import java.lang.reflect.Field
import java.util.*


interface ProgramChangeSnapshotStrategy<out T : Any, in OldT : Any, in NewT : Any> {
    fun snapshot(old: OldT, new: NewT): T
}

typealias ErasedProgramChangeSnapshotStrategy = ProgramChangeSnapshotStrategy<Any, Any, Any>

data class ProgramChangeEventInterest<T : Any>(
    val event: EventType,
    val snapshotPolicy: ProgramChangeSnapshotStrategy<T, Any, Any>
)

data class ProgramChange<T>(val eventType: EventType, val program: Program, val value: T)

data class ErasedEventInterestInfo(val snapshotStrategy: ErasedProgramChangeSnapshotStrategy, val ty: Class<*>)

class ProgramChangeWatcher(private val scope: CoroutineScope) : DomainObjectListener {
    companion object {
        val bitfield: Field = DomainObjectChangedEvent::class.java.getDeclaredField("eventBits")

        init {
            bitfield.isAccessible = true
        }
    }

    private val interestTable = arrayOfNulls<ErasedEventInterestInfo>(255)
    private val interestBits = BitSet(255)

    private val changeChannel = Channel<ProgramChange<Any>>(
        capacity = BUFFERED,
        onBufferOverflow = BufferOverflow.SUSPEND,
    )

    private val changeFlow = changeChannel.receiveAsFlow()

    fun <T : Any> registerInterest(group: ProgramChangeEventInterest<T>): Flow<ProgramChange<T>> {
        return changeFlow.mapNotNull {
            if (it.eventType != group.event) {
                null
            } else {
                @Suppress("UNCHECKED_CAST")
                it as ProgramChange<T>
            }
        }
    }

    override fun domainObjectChanged(ev: DomainObjectChangedEvent) {
        val eventBits = bitfield.get(ev) as? BitSet ?: error("Unexpected type for eventBits!")
        if (!eventBits.intersects(interestBits)) {
            return
        }

        scope.launch {
            val program = ev.source as Program

            for (change in ev) {
                // Verified to be non-null by the `eventBits` intersection.
                val info = interestTable[change.eventType.id]!!
                val snapshot = info.snapshotStrategy.snapshot(change.oldValue, change.newValue)

                changeChannel.send(ProgramChange(change.eventType, program, snapshot))
            }
        }
    }
}