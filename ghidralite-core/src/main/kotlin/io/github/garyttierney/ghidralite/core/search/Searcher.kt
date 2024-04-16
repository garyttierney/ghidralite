package io.github.garyttierney.ghidralite.core.search

import com.intellij.psi.codeStyle.NameUtil
import io.github.garyttierney.ghidralite.core.db.SymbolLookupDetails
import io.github.garyttierney.ghidralite.core.search.index.Indexes
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.scan
import java.util.*
import java.util.concurrent.PriorityBlockingQueue
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration.Companion.milliseconds

class Searcher(private val indexes: Indexes) {
    @OptIn(FlowPreview::class)
    suspend fun query(query: String, onDataAvailable: (List<SearchResult>) -> Unit) {
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

        indexes.query<SymbolLookupDetails>()
            .scan(PriorityQueue(naturalOrder<SearchResult>().reversed())) { queue, item ->
                val parentScore = if (parent.isNotEmpty()) {
                    val score = item.parent?.let { parent -> parentMatcher.matchingDegree(parent.label, false) }
                    score ?: 0
                } else {
                    1
                }

                val labelScore = if (label.isNotEmpty()) {
                    labelMatcher.matchingDegree(item.label, false)
                } else {
                    1
                }

                val score = labelScore + parentScore

                if (score < 2) {
                    return@scan queue
                }

                val beatsWorst = queue.size == queueCapacity && queue.peek().score < score
                val adding = beatsWorst || queue.size < queueCapacity

                if (adding) {
                    val fragments = labelMatcher.matchingFragments(item.label) ?: mutableListOf()
                    val result = SearchResult(
                        item,
                        score,
                        fragments.map { it.startOffset.rangeTo(it.startOffset + it.length) }
                    )

                    queue.add(result)
                }

                queue
            }
            .debounce(100.milliseconds)
            .conflate()
            .collect {
                onDataAvailable(it.toList())
            }
    }
}

