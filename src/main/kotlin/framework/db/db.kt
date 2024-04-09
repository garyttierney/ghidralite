package io.github.garyttierney.ghidralite.framework.db

import db.DBRecord
import db.RecordIterator
import db.Table

interface Record {
    val inner: DBRecord
}

fun RecordIterator.asSequence() = sequence {
    while (hasNext()) {
        yield(next())
    }
}

abstract class GhidraTable<T : Record>(private val table: Table) {
    protected abstract fun from(record: DBRecord): T

    fun allAfter(since: Long = Long.MIN_VALUE) = table.iterator(since).asSequence()
}
