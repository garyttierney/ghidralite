package io.github.garyttierney.ghidralite.core.search.index.program


interface ProgramChangeSnapshotStrategy<out T : Any> {
    fun snapshot(event: Int, old: Any, new: Any): T
}

typealias ErasedProgramChangeSnapshotStrategy = ProgramChangeSnapshotStrategy<Any>

data class ProgramChangeInterest<T : Any>(
    val events: Set<Int>,
    val snapshotPolicy: ProgramChangeSnapshotStrategy<T>
)

fun <T : Any> programChangeInterest(policy: ProgramChangeSnapshotStrategy<T>, vararg eventTypes: Int) =
    ProgramChangeInterest(eventTypes.toSet(), policy)

data class ErasedEventInterestInfo(val snapshotStrategy: ErasedProgramChangeSnapshotStrategy, val ty: Class<*>)