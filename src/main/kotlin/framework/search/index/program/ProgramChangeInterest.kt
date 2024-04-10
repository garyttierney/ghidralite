package io.github.garyttierney.ghidralite.framework.search.index.program

import ghidra.framework.model.EventType

interface ProgramChangeSnapshotStrategy<out T : Any> {
    fun snapshot(event: EventType, old: Any, new: Any): T
}

typealias ErasedProgramChangeSnapshotStrategy = ProgramChangeSnapshotStrategy<Any>

data class ProgramChangeInterest<T : Any>(
    val events: Set<EventType>,
    val snapshotPolicy: ProgramChangeSnapshotStrategy<T>
)

fun <T : Any> programChangeInterest(policy: ProgramChangeSnapshotStrategy<T>, vararg eventTypes: EventType) =
    ProgramChangeInterest(eventTypes.toSet(), policy)

data class ErasedEventInterestInfo(val snapshotStrategy: ErasedProgramChangeSnapshotStrategy, val ty: Class<*>)