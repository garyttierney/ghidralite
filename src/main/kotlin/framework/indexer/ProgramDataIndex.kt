package io.github.garyttierney.ghidralite.framework.indexer

interface ProgramDataIndex<T : Any> {
    val changeInterest: ProgramChangeEventInterest<T>
}