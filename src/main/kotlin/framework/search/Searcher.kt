package io.github.garyttierney.ghidralite.framework.search

import com.intellij.openapi.util.TextRange
import com.intellij.psi.codeStyle.NameUtil
import io.github.garyttierney.ghidralite.framework.LookupElement
import io.github.garyttierney.ghidralite.framework.db.SymbolLookupDetails
import io.github.garyttierney.ghidralite.framework.search.index.Indexes
import java.util.concurrent.PriorityBlockingQueue
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.max

class Searcher(private val indexes: Indexes) {
    suspend fun query(query: String, onDataAvailable: (List<SearchResult>) -> Unit) {
        val priorityQueue = PriorityBlockingQueue<SearchResult>()
        val emissions = AtomicInteger(0)

        val queueCapacity = 50
        val label = query.substringAfterLast("::")
        val parent = query.substringBeforeLast("::", missingDelimiterValue = "")

        val parentMatcher = NameUtil.buildMatcher(parent)
            .withCaseSensitivity(NameUtil.MatchingCaseSensitivity.NONE)
            .withSeparators("_")
            .preferringStartMatches()
            .typoTolerant()
            .build()

        val labelMatcher = NameUtil.buildMatcher(label)
            .withCaseSensitivity(NameUtil.MatchingCaseSensitivity.NONE)
            .withSeparators("_")
            .typoTolerant()
            .build()

        indexes.query<SymbolLookupDetails>().collect {
            val parentScore = if (parent.isNotEmpty()) {
                val score = it.parent?.let { parent -> parentMatcher.matchingDegree(parent.label, false) }
                score ?: 0
            } else {
                1
            }

            val labelScore = if (label.isNotEmpty()) {
                labelMatcher.matchingDegree(it.label, false)
            } else {
                1
            }

            val score = labelScore + parentScore

            if (score < 2) {
                return@collect
            }

            val beatsWorst = priorityQueue.size == queueCapacity && priorityQueue.peek().score < score
            val adding = beatsWorst || priorityQueue.size < queueCapacity

            if (adding) {
                val fragments = labelMatcher.matchingFragments(it.label) ?: mutableListOf()
                val result = SearchResult(it, score, fragments)

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
    val element: LookupElement,
    val score: Int,
    val fragments: MutableList<TextRange>
) : Comparable<SearchResult> {
    override fun compareTo(other: SearchResult): Int = score.compareTo(other.score)
}