package io.github.garyttierney.ghidralite.core.db

import db.DBRecord
import db.RecordIterator
import db.Table
import java.util.*
import java.util.Spliterator.SORTED
import java.util.function.Consumer
import java.util.stream.StreamSupport

interface GhidraRecord {
    val inner: DBRecord
    val key: Long
        get() = inner.key
}

fun RecordIterator.asSequence() = sequence {
    while (hasNext()) {
        yield(next())
    }
}

class GhidraRecordSpliterator<T : GhidraRecord>(
    private val table: GhidraTable<T>,
    private var start: Long,
    private val end: Long,
    private var inner: RecordIterator,
    private var exactSize: Long?
) : Spliterator<T> {
    override fun tryAdvance(action: Consumer<in T>): Boolean {
        if (!inner.hasNext()) {
            return false
        }

        action.accept(table.from(inner.next()))
        return true
    }

    override fun getExactSizeIfKnown(): Long = end - start

    override fun trySplit(): Spliterator<T>? {
        val lo = start // divide range in half
        val mid = ((lo + end + 1) ushr 1) and 1.inv() // force midpoint to be even
        if (lo < mid) { // split out left half
            start = mid // reset this Spliterator's origin
            inner = table.inner.iterator(start, end, start)

            if (exactSize != null) {
                exactSize = exactSize!! - (start - lo)
            }

            return GhidraRecordSpliterator(table, lo, mid, table.inner.iterator(lo, mid, lo), null)
        } else  // too small to split
            return null
    }

    override fun estimateSize() = end - start

    override fun characteristics(): Int {
        return SORTED or Spliterator.ORDERED or Spliterator.NONNULL or Spliterator.SIZED or Spliterator.SUBSIZED or Spliterator.CONCURRENT
    }

    override fun getComparator(): Comparator<in T> = Comparator.comparing { it.inner.key }
}

abstract class GhidraTable<T : GhidraRecord>(val inner: Table) {
    internal abstract fun from(record: DBRecord): T

    fun get(id: Long) = from(inner.getRecord(id))

    fun all() = StreamSupport.stream(
        GhidraRecordSpliterator(
            this,
            0,
            inner.maxKey,
            inner.iterator(),
            inner.recordCount.toLong()
        ),
        true
    )

    fun allAfter(since: Long = Long.MIN_VALUE) = inner.iterator(since).asSequence().map(::from)
}
