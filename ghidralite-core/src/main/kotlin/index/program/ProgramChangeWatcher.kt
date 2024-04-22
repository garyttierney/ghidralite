package io.github.garyttierney.ghidralite.core.search.index.program

import ghidra.framework.model.DomainObjectChangedEvent
import ghidra.framework.model.DomainObjectListener
import ghidra.program.util.ProgramChangeRecord
import io.github.garyttierney.ghidralite.core.index.change.IndexChange
import io.github.garyttierney.ghidralite.core.index.change.IndexChangeFlowProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.Channel.Factory.BUFFERED
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import java.lang.reflect.Field
import java.util.*
import kotlin.reflect.KClass

data class ProgramChangeGroup<T : Any>(
    val type: KClass<T>,
    val addedEvent: Int,
    val changedEvents: Set<Int>,
    val removedEvent: Int
)


class ProgramChangeWatcher(private val scope: CoroutineScope) : DomainObjectListener {
    companion object {
        val bitfield: Field = DomainObjectChangedEvent::class.java.getDeclaredField("eventBits")

        init {
            bitfield.isAccessible = true
        }
    }

    private val interestTable = arrayOfNulls<ProgramChangeGroup<out Any>>(255)
    private val interestBits = BitSet(255)

    private val changeChannel = Channel<IndexChange<Any>>(
        capacity = BUFFERED,
        onBufferOverflow = BufferOverflow.SUSPEND,
    )

    fun <T : Any> registerInterest(
        type: KClass<T>,
        addedEvent: Int,
        removedEvent: Int,
        vararg changeEvents: Int
    ): IndexChangeFlowProvider<T> {
        val group = ProgramChangeGroup(type, addedEvent, changeEvents.toSet(), removedEvent)
        val eventSet = group.changedEvents + addedEvent + removedEvent

        eventSet.forEach {
            interestBits.set(it)
            interestTable[it] = group
        }

        return object : IndexChangeFlowProvider<T> {
            override fun getFlow(): Flow<IndexChange<T>> {
                @Suppress("UNCHECKED_CAST")
                return changeChannel
                    .receiveAsFlow()
                    .filter { type.java.isAssignableFrom(it.value.javaClass) } as Flow<IndexChange<T>>
            }
        }
    }

    inline fun <reified T : Any> registerInterest(addedEvent: Int, removedEvent: Int, vararg changeEvents: Int) =
        registerInterest(T::class, addedEvent, removedEvent, *changeEvents)


    override fun domainObjectChanged(ev: DomainObjectChangedEvent) {
        val eventBits = bitfield.get(ev) as? BitSet ?: error("Unexpected type for eventBits!")
        if (!eventBits.intersects(interestBits)) {
            return
        }

        scope.launch {
            for (changeRecord in ev) {
                changeRecord as ProgramChangeRecord

                val obj = changeRecord.`object`
                val group = interestTable[changeRecord.eventType] ?: error("No change group found")

                val change = when (changeRecord.eventType) {
                    group.addedEvent -> IndexChange.Added(obj)
                    group.removedEvent -> IndexChange.Removed(obj)
                    else -> IndexChange.Replaced(obj)
                }

                changeChannel.send(change)
            }
        }
    }
}