package io.github.garyttierney.ghidralite.framework.search

import com.intellij.openapi.util.TextRange
import com.intellij.psi.codeStyle.NameUtil
import io.github.garyttierney.ghidralite.framework.db.SymbolRecord
import io.github.garyttierney.ghidralite.framework.search.index.Indexes
import java.util.concurrent.PriorityBlockingQueue
import java.util.concurrent.atomic.AtomicInteger

public class Searcher(val indexes: Indexes) {
    public suspend fun query(query: String, onDataAvailable: (List<SearchResult>) -> Unit) {
        val priorityQueue = PriorityBlockingQueue<SearchResult>()
        val emissions = AtomicInteger(0)

        val queueCapacity = 50
        val matcher = NameUtil.buildMatcher(query).withCaseSensitivity(NameUtil.MatchingCaseSensitivity.NONE)
            .withSeparators(".:_").typoTolerant().allOccurrences().build()

        indexes.query<SymbolRecord>().collect {
            val matchingDegree = matcher.matchingDegree(it.name, false)
            val result = when {
                matchingDegree < 1 -> return@collect
                else -> SearchResult(it.name, it.name, it.name, matchingDegree, it.key, mutableListOf())
            }

            val beatsWorst = priorityQueue.size == queueCapacity && priorityQueue.peek().score < result.score
            val adding = beatsWorst || priorityQueue.size < queueCapacity

            if (adding) {
                val fragments = matcher.matchingFragments(it.name)
                result.fragments.addAll(fragments)
                priorityQueue.add(result)

                if (emissions.incrementAndGet() >= 50) {
                    onDataAvailable(priorityQueue.toList().reversed())
                    emissions.set(0)
                }
            }
        }

        onDataAvailable(priorityQueue.toList().reversed())
    }
}

data class SearchResult(
    val name: String,
    val subheading: String,
    val type: String,
    val score: Int,
    val uniqueKey: Long,
    val fragments: MutableList<TextRange>
) : Comparable<SearchResult> {
    override fun compareTo(other: SearchResult): Int = score.compareTo(other.score)
}